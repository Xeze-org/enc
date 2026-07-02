// enc - AES-256-GCM encryption for files and folders (Rust).
// See ../SPEC.md for the shared byte layout.
//
// Commands:
//   enc keygen                     Generate a reusable key (store it safely!)
//   enc encrypt <path> [out]       Encrypt a file OR folder (auto-detects)
//   enc decrypt <file.enc> [dest]  Decrypt (auto-detects file vs folder)
//   enc encrypt-dir / decrypt-dir  Force folder mode (kept for interop)
//   enc help                       Show usage

use std::env;
use std::fs;
use std::io::{IsTerminal, Read, Write};
use std::path::Path;
use std::process::exit;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 4] = b"ENC1";
const VERSION: u8 = 1; // output format v1 (universal); decrypt can still read v2
const HEADER_LEN: usize = 5; // MAGIC(4) + version(1)
const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;
const SHA_LEN: usize = 32;
const SALT_LEN: usize = 16;
const VERSION_PW: u8 = 3; // password mode: key = scrypt(password, salt)

// ------------------------- crypto core -------------------------

/// v1 format. Blob = MAGIC | 0x01 | IV(12) | ciphertext | tag(16).
fn encrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err("key must be 32 bytes".into());
    }

    let header = [MAGIC[0], MAGIC[1], MAGIC[2], MAGIC[3], VERSION];
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut iv = [0u8; IV_LEN];
    getrandom::getrandom(&mut iv).map_err(|e| e.to_string())?;
    let nonce = Nonce::from_slice(&iv);

    let ct_and_tag = cipher
        .encrypt(nonce, Payload { msg: data, aad: &header })
        .map_err(|_| "encryption failed".to_string())?;

    let mut out = Vec::with_capacity(HEADER_LEN + IV_LEN + ct_and_tag.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&iv);
    out.extend_from_slice(&ct_and_tag);
    Ok(out)
}

/// Returns (plaintext, Some(sha256_hex)) — the hash is present only for v2 blobs
/// (v1, and blobs from the other languages, decrypt with no embedded hash).
fn decrypt(blob: &[u8], key: &[u8]) -> Result<(Vec<u8>, Option<String>), String> {
    if key.len() != 32 {
        return Err("key must be 32 bytes".into());
    }
    if blob.len() < HEADER_LEN + IV_LEN + TAG_LEN {
        return Err("blob too short".into());
    }
    if &blob[..4] != MAGIC {
        return Err("bad magic (not an enc file)".into());
    }
    let version = blob[4];
    let header = &blob[..HEADER_LEN]; // AAD binds magic + version

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let iv = &blob[HEADER_LEN..HEADER_LEN + IV_LEN];
    let ct_and_tag = &blob[HEADER_LEN + IV_LEN..];
    let nonce = Nonce::from_slice(iv);

    let recovered = cipher
        .decrypt(nonce, Payload { msg: ct_and_tag, aad: header })
        .map_err(|_| "message authentication failed".to_string())?;

    match version {
        1 => Ok((recovered, None)),
        2 => {
            if recovered.len() < SHA_LEN {
                return Err("corrupt: missing integrity hash".into());
            }
            let (stored, data) = recovered.split_at(SHA_LEN);
            let actual = Sha256::digest(data);
            if actual.as_slice() != stored {
                return Err("SHA-256 integrity check FAILED".into());
            }
            Ok((data.to_vec(), Some(hex::encode(actual))))
        }
        v => Err(format!("unsupported format version {v}")),
    }
}

fn build_tar(src_dir: &str) -> Result<Vec<u8>, String> {
    let mut builder = tar::Builder::new(Vec::new());
    builder.follow_symlinks(false);
    builder.append_dir_all(".", src_dir).map_err(|e| e.to_string())?;
    builder.into_inner().map_err(|e| e.to_string())
}

fn encrypt_dir(src_dir: &str, key: &[u8]) -> Result<Vec<u8>, String> {
    encrypt(&build_tar(src_dir)?, key)
}

// ---- password mode (v3): key = scrypt(password, salt) ----

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let params = scrypt::Params::new(15, 8, 1, 32).map_err(|e| e.to_string())?;
    let mut key = [0u8; 32];
    scrypt::scrypt(password.as_bytes(), salt, &params, &mut key).map_err(|e| e.to_string())?;
    Ok(key)
}

/// v3 blob: MAGIC | 0x03 | salt(16) | IV(12) | ciphertext | tag(16)
fn encrypt_pw(data: &[u8], password: &str) -> Result<Vec<u8>, String> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::getrandom(&mut salt).map_err(|e| e.to_string())?;
    let key = derive_key(password, &salt)?;

    let mut header = Vec::with_capacity(HEADER_LEN + SALT_LEN);
    header.extend_from_slice(MAGIC);
    header.push(VERSION_PW);
    header.extend_from_slice(&salt);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let mut iv = [0u8; IV_LEN];
    getrandom::getrandom(&mut iv).map_err(|e| e.to_string())?;
    let nonce = Nonce::from_slice(&iv);
    let ct_and_tag = cipher
        .encrypt(nonce, Payload { msg: data, aad: &header })
        .map_err(|_| "encryption failed".to_string())?;

    let mut out = Vec::with_capacity(header.len() + IV_LEN + ct_and_tag.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&iv);
    out.extend_from_slice(&ct_and_tag);
    Ok(out)
}

fn decrypt_pw(blob: &[u8], password: &str) -> Result<Vec<u8>, String> {
    if blob.len() < HEADER_LEN + SALT_LEN + IV_LEN + TAG_LEN {
        return Err("blob too short".into());
    }
    if &blob[..4] != MAGIC || blob[4] != VERSION_PW {
        return Err("not a password-mode file".into());
    }
    let salt = &blob[HEADER_LEN..HEADER_LEN + SALT_LEN];
    let header = &blob[..HEADER_LEN + SALT_LEN]; // AAD
    let iv = &blob[HEADER_LEN + SALT_LEN..HEADER_LEN + SALT_LEN + IV_LEN];
    let ct_and_tag = &blob[HEADER_LEN + SALT_LEN + IV_LEN..];

    let key = derive_key(password, salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let nonce = Nonce::from_slice(iv);
    cipher
        .decrypt(nonce, Payload { msg: ct_and_tag, aad: header })
        .map_err(|_| "wrong password or corrupted file".to_string())
}

/// Read the format version byte without decrypting.
fn peek_version(blob: &[u8]) -> Result<u8, String> {
    if blob.len() < HEADER_LEN + IV_LEN + TAG_LEN {
        return Err("blob too short".into());
    }
    if &blob[..4] != MAGIC {
        return Err("bad magic (not an enc file)".into());
    }
    Ok(blob[4])
}

fn unpack_tar(tar_bytes: &[u8], dest_dir: &str) -> Result<(), String> {
    fs::create_dir_all(dest_dir).map_err(|e| e.to_string())?;
    let mut archive = tar::Archive::new(tar_bytes);
    archive.unpack(dest_dir).map_err(|e| e.to_string())
}

fn looks_like_tar(data: &[u8]) -> bool {
    data.len() >= 512 && &data[257..262] == b"ustar"
}

// ------------------------- naming & sizes -------------------------

fn default_enc_name(input: &str) -> String {
    let base = Path::new(input)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "output".into());
    format!("{base}.enc")
}

fn default_dec_base(input: &str) -> String {
    let base = Path::new(input)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "output".into());
    match base.strip_suffix(".enc") {
        Some(stripped) if !stripped.is_empty() => stripped.to_string(),
        _ => format!("{base}.out"),
    }
}

/// Total size of a file, or the sum of all files in a folder (recursive).
fn path_size(p: &Path) -> u64 {
    match fs::metadata(p) {
        Ok(m) if m.is_file() => m.len(),
        Ok(m) if m.is_dir() => fs::read_dir(p)
            .map(|rd| rd.flatten().map(|e| path_size(&e.path())).sum())
            .unwrap_or(0),
        _ => 0,
    }
}

fn human_size(b: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut f = b as f64;
    let mut i = 0;
    while f >= 1024.0 && i < U.len() - 1 {
        f /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{b} B")
    } else {
        format!("{f:.1} {}", U[i])
    }
}

// ------------------------- pretty output -------------------------

fn color_enabled() -> bool {
    static C: OnceLock<bool> = OnceLock::new();
    *C.get_or_init(|| {
        if env::var_os("NO_COLOR").is_some() {
            return false;
        }
        if env::var_os("CLICOLOR_FORCE").is_some() {
            return true;
        }
        std::io::stderr().is_terminal()
    })
}

fn paint(code: &str, s: &str) -> String {
    if color_enabled() {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}
fn green(s: &str) -> String { paint("1;32", s) }
fn bold(s: &str) -> String { paint("1", s) }
fn dim(s: &str) -> String { paint("2", s) }
fn cyan(s: &str) -> String { paint("36", s) }
fn yellow(s: &str) -> String { paint("1;33", s) }

/// Enable ANSI escape processing on modern Windows consoles.
#[cfg(windows)]
fn enable_vt() {
    use std::os::windows::io::AsRawHandle;
    #[link(name = "kernel32")]
    extern "system" {
        fn GetConsoleMode(h: *mut core::ffi::c_void, m: *mut u32) -> i32;
        fn SetConsoleMode(h: *mut core::ffi::c_void, m: u32) -> i32;
    }
    let h = std::io::stderr().as_raw_handle() as *mut core::ffi::c_void;
    unsafe {
        let mut mode = 0u32;
        if GetConsoleMode(h, &mut mode) != 0 {
            let _ = SetConsoleMode(h, mode | 0x0004); // ENABLE_VIRTUAL_TERMINAL_PROCESSING
        }
    }
}
#[cfg(not(windows))]
fn enable_vt() {}

/// A nice summary block for an encrypt/decrypt operation.
fn report(action: &str, kind: &str, name: &str, out: &str, in_sz: u64, out_sz: u64, dur: Duration) {
    let mark = if color_enabled() { "✓" } else { "OK" };
    let arrow = if color_enabled() { "→" } else { "->" };

    eprintln!("{} {} {}  {}", green(mark), action, kind, bold(name));
    eprintln!("   {}  {}", dim(&format!("{:<7}", "output")), cyan(out));
    eprintln!(
        "   {}  {} {} {}",
        dim(&format!("{:<7}", "size")),
        human_size(in_sz),
        dim(arrow),
        human_size(out_sz)
    );
    eprintln!("   {}  {} ms", dim(&format!("{:<7}", "time")), dur.as_millis());
}

// ------------------------- keys -------------------------

// Read a secret from the terminal with echo disabled (Windows), falling back
// to a plain read elsewhere or when stdin isn't a console.
#[cfg(windows)]
fn without_echo<R>(f: impl FnOnce() -> R) -> R {
    use std::os::windows::io::AsRawHandle;
    #[link(name = "kernel32")]
    extern "system" {
        fn GetConsoleMode(h: *mut core::ffi::c_void, m: *mut u32) -> i32;
        fn SetConsoleMode(h: *mut core::ffi::c_void, m: u32) -> i32;
    }
    const ENABLE_ECHO_INPUT: u32 = 0x0004;
    let h = std::io::stdin().as_raw_handle() as *mut core::ffi::c_void;
    let mut mode = 0u32;
    let ok = unsafe { GetConsoleMode(h, &mut mode) != 0 };
    if ok {
        unsafe { SetConsoleMode(h, mode & !ENABLE_ECHO_INPUT) };
    }
    let r = f();
    if ok {
        unsafe { SetConsoleMode(h, mode) };
    }
    r
}
#[cfg(not(windows))]
fn without_echo<R>(f: impl FnOnce() -> R) -> R {
    f()
}

fn prompt_secret(msg: &str) -> String {
    eprint!("{msg}");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    without_echo(|| {
        let _ = std::io::stdin().read_line(&mut line);
    });
    eprintln!(); // newline after the hidden input
    line.trim_end_matches(['\r', '\n']).to_string()
}

/// Resolve the decryption key: inline `-np` value, else ENC_KEY, else prompt
/// (if a terminal), else error.
fn resolve_key(np: &Option<String>) -> Vec<u8> {
    let key_hex = match np {
        Some(s) => s.clone(),
        None => match env::var("ENC_KEY") {
            Ok(v) if !v.is_empty() => v,
            _ => {
                if std::io::stdin().is_terminal() {
                    prompt_secret("Enter key (64 hex chars): ")
                } else {
                    eprintln!("{}", yellow("key required: set ENC_KEY or pass -np <hexkey>"));
                    exit(1);
                }
            }
        },
    };
    match hex::decode(key_hex.trim()) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("bad key hex: {e}");
            exit(1);
        }
    }
}

/// Resolve the password: inline `-np` value, else ENC_PASS, else prompt (if a
/// terminal), else error.
fn resolve_password(np: &Option<String>) -> String {
    if let Some(s) = np {
        return s.clone();
    }
    match env::var("ENC_PASS") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            if std::io::stdin().is_terminal() {
                prompt_secret("Enter password: ")
            } else {
                eprintln!("{}", yellow("password required: set ENC_PASS or pass -np <password>"));
                exit(1);
            }
        }
    }
}

/// Decide the smart-mode action for `enc <path>`: encrypt plaintext, decrypt
/// an existing enc file.
fn decide_smart(path: &str) -> &'static str {
    match fs::metadata(path) {
        Ok(m) if m.is_dir() => "encrypt", // a folder is always plaintext input
        Ok(_) => {
            let mut buf = [0u8; 4];
            let n = fs::File::open(path)
                .and_then(|mut f| f.read(&mut buf))
                .unwrap_or(0);
            if n >= 4 && &buf == MAGIC {
                "decrypt"
            } else {
                "encrypt"
            }
        }
        Err(e) => {
            eprintln!("error: cannot read '{path}': {e}");
            exit(1);
        }
    }
}

fn key_for_encrypt(np: &Option<String>) -> (Vec<u8>, Option<String>) {
    let provided = match np {
        Some(s) => Some(s.clone()),
        None => env::var("ENC_KEY").ok().filter(|v| !v.is_empty()),
    };
    match provided {
        Some(v) => match hex::decode(v.trim()) {
            Ok(k) => (k, None),
            Err(e) => {
                eprintln!("bad key hex: {e}");
                exit(1);
            }
        },
        None => {
            let mut key = [0u8; 32];
            if let Err(e) = getrandom::getrandom(&mut key) {
                eprintln!("error: {e}");
                exit(1);
            }
            (key.to_vec(), Some(hex::encode(key)))
        }
    }
}

fn keygen() -> Result<(), String> {
    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key).map_err(|e| e.to_string())?;
    let hex_key = hex::encode(key);

    println!("{hex_key}"); // stdout: the key itself

    eprintln!();
    eprintln!("{}", yellow("  NEW 32-byte key generated (the line above)  "));
    eprintln!();
    eprintln!("{}", bold("STORE IT IN A PASSWORD MANAGER NOW (Bitwarden, 1Password, KeePass):"));
    eprintln!("   {} lose it  {} encrypted data is gone forever (no recovery)", dim("*"), dim("->"));
    eprintln!("   {} leak it  {} anyone with it can decrypt your files", dim("*"), dim("->"));
    eprintln!("   {} decrypt with the SAME key you encrypted with", dim("*"));
    eprintln!();
    eprintln!("Load it:  {}", cyan(&format!("$env:ENC_KEY = \"{hex_key}\"")));
    Ok(())
}

fn announce_key(out_path: &str, hex_key: &str) {
    println!("{hex_key}"); // stdout: the key (scriptable)
    eprintln!();
    eprintln!("{}", yellow("  NEW per-file key - SAVE THIS NOW  "));
    eprintln!("   {}", bold(hex_key));
    eprintln!("   {} {}", dim("store in your password manager, labeled:"), cyan(out_path));
    eprintln!("   {}", dim("without it, this file can never be decrypted."));
}

/// Generate a strong random password from a mixed character set (rejection
/// sampling -> no modulo bias).
fn genpass(len: usize) -> Result<String, String> {
    const CHARS: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}:,.?";
    let n = CHARS.len();
    let max = (256 / n) * n; // reject bytes >= max so every char is equally likely
    let mut out = String::with_capacity(len);
    let mut byte = [0u8; 1];
    while out.len() < len {
        getrandom::getrandom(&mut byte).map_err(|e| e.to_string())?;
        let b = byte[0] as usize;
        if b < max {
            out.push(CHARS[b % n] as char);
        }
    }
    Ok(out)
}

/// Compute (and optionally verify) the SHA-256 of a file.
fn sha256_cmd(path: &str, expected: Option<&str>) {
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: cannot read '{path}': {e}");
            exit(1);
        }
    };
    let hash = hex::encode(Sha256::digest(&data));
    match expected {
        None => {
            // sha256sum-compatible: "<hex>  <file>"
            println!("{hash}  {path}");
        }
        Some(exp) => {
            if hash.eq_ignore_ascii_case(exp.trim()) {
                let mark = if color_enabled() { "✓" } else { "OK" };
                eprintln!("{} sha256 matches  {}", green(mark), dim(path));
            } else {
                let mark = if color_enabled() { "✗" } else { "x" };
                eprintln!("{} {}", mark, yellow("sha256 MISMATCH"));
                eprintln!("   {}  {}", dim("expected"), exp.trim());
                eprintln!("   {}  {}", dim("actual  "), hash);
                exit(1);
            }
        }
    }
}

fn print_help() {
    eprintln!(
"{title}

USAGE:
  enc <path>                       Smart: encrypt if plaintext, decrypt if .enc
                                   (prompts for key/password when decrypting)
  enc keygen                       Generate a reusable key (then store it safely!)
  enc -p [length]                  Generate a strong random password (default 24)
  enc -p [length] <path>           Encrypt that file/folder with a generated password
  enc sha256 <file> [expected]     Print a file's SHA-256, or verify it
  enc encrypt   <path>  [out]      Encrypt a FILE or FOLDER (auto-detected)
  enc encrypt -p [length] <path>   Encrypt with a generated PASSWORD (printed)
  enc decrypt   <file.enc> [dest]  Decrypt; auto-detects file vs folder
  enc encrypt-dir / decrypt-dir    Force folder mode (needs explicit [out])
  enc help                         Show this help

  -np <secret>                     No-prompt (scripts): use <secret> as the key
                                   or password inline. Works with any command,
                                   e.g.  enc file.enc -np <hexkey-or-password>

KEY / PASSWORD:
  Key mode:      if ENC_KEY is set it's used; otherwise encrypt generates a
                 per-file key and prints it. Decrypt needs ENC_KEY.
  Password mode: 'encrypt -p' generates a password and prints it. To decrypt,
                 set ENC_PASS to that password (enc detects password files).
    PowerShell:  $env:ENC_KEY = \"<hex>\"   /   $env:ENC_PASS = \"<password>\"
    Git Bash:    export ENC_KEY=\"<hex>\"    /   export ENC_PASS=\"<password>\"
  Make a reusable key with:  enc keygen",
        title = bold("enc - AES-256-GCM encryption for files and folders")
    );
}

// ------------------------- main -------------------------

/// Parse `[length] [path]` that may follow a `-p` flag. A leading numeric token
/// is the length (default 24); the next token, if any, is the path.
fn parse_len_and_path(rest: &[String]) -> (usize, Option<&str>) {
    let mut idx = 0;
    let len = match rest.first() {
        Some(t) => match t.parse::<usize>() {
            Ok(n) => {
                idx = 1;
                n
            }
            Err(_) => 24,
        },
        None => 24,
    };
    (len, rest.get(idx).map(String::as_str))
}

/// Generate a password, derive a key via scrypt, encrypt `path` in password
/// mode, and print the password to save.
fn encrypt_with_password(len: usize, path: &str) {
    let password = match genpass(len) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            exit(1);
        }
    };

    let is_dir = match fs::metadata(path) {
        Ok(m) => m.is_dir(),
        Err(e) => {
            eprintln!("error: cannot read '{path}': {e}");
            exit(1);
        }
    };
    let out_path = default_enc_name(path);
    let in_sz = path_size(Path::new(path));

    let t0 = Instant::now();
    let res = if is_dir {
        build_tar(path)
            .and_then(|t| encrypt_pw(&t, &password))
            .and_then(|o| fs::write(&out_path, o).map_err(|e| e.to_string()))
    } else {
        fs::read(path)
            .map_err(|e| e.to_string())
            .and_then(|d| encrypt_pw(&d, &password))
            .and_then(|o| fs::write(&out_path, o).map_err(|e| e.to_string()))
    };
    let dur = t0.elapsed();
    if let Err(e) = res {
        eprintln!("error: {e}");
        exit(1);
    }

    let out_sz = fs::metadata(&out_path).map(|m| m.len()).unwrap_or(0);
    report("Encrypted", if is_dir { "folder" } else { "file" }, path, &out_path, in_sz, out_sz, dur);

    println!("{password}"); // stdout: the password (scriptable)
    eprintln!();
    eprintln!("{}", yellow("  NEW password - SAVE THIS NOW  "));
    eprintln!("   {}", bold(&password));
    eprintln!("   {}", dim("to decrypt later, set ENC_PASS to this password:"));
    eprintln!("   {}", cyan(&format!("$env:ENC_PASS = \"{password}\";  enc decrypt {out_path}")));
}

fn main() {
    enable_vt();

    // Pull out `-np <secret>` (no-prompt: supply key/password inline for
    // scripts) before positional parsing, so it can appear anywhere.
    let raw: Vec<String> = env::args().collect();
    let mut np_secret: Option<String> = None;
    let mut args: Vec<String> = Vec::with_capacity(raw.len());
    let mut ri = 0;
    while ri < raw.len() {
        if raw[ri] == "-np" {
            match raw.get(ri + 1) {
                Some(s) => {
                    np_secret = Some(s.clone());
                    ri += 2;
                }
                None => {
                    eprintln!("usage: -np <key-or-password>");
                    exit(1);
                }
            }
        } else {
            args.push(raw[ri].clone());
            ri += 1;
        }
    }
    let cmd = args.get(1).map(String::as_str).unwrap_or("help");

    match cmd {
        "help" | "-h" | "--help" => {
            print_help();
            return;
        }
        "keygen" => {
            if let Err(e) = keygen() {
                eprintln!("error: {e}");
                exit(1);
            }
            return;
        }
        "-p" | "password" | "pass" => {
            let (len, path) = parse_len_and_path(&args[2..]);
            match path {
                // enc -p [len] <path>  -> encrypt that file/folder with a password
                Some(p) => encrypt_with_password(len, p),
                // enc -p [len]         -> just generate and print a password
                None => match genpass(len) {
                    Ok(pw) => {
                        println!("{pw}");
                        eprintln!();
                        eprintln!(
                            "{}",
                            dim(&format!("generated a {len}-char password - store it in your password manager"))
                        );
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        exit(1);
                    }
                },
            }
            return;
        }
        "sha256" | "hash" => {
            let path = match args.get(2) {
                Some(p) => p.as_str(),
                None => {
                    eprintln!("usage: enc sha256 <file> [expected-hex]");
                    exit(1);
                }
            };
            sha256_cmd(path, args.get(3).map(String::as_str));
            return;
        }
        _ => {}
    }

    // Smart mode: if arg 1 isn't a subcommand, treat it as a path and pick the
    // direction automatically (plaintext -> encrypt, enc file -> decrypt).
    let is_subcommand = matches!(cmd, "encrypt" | "decrypt" | "encrypt-dir" | "decrypt-dir");
    let (cmd, in_path, out_arg): (&str, &str, Option<&str>) = if is_subcommand {
        let ip = match args.get(2) {
            Some(p) => p.as_str(),
            None => {
                print_help();
                exit(1);
            }
        };
        (cmd, ip, args.get(3).map(String::as_str))
    } else {
        (decide_smart(cmd), cmd, None)
    };

    match cmd {
        "encrypt" | "encrypt-dir" => {
            // Password mode: enc encrypt -p [length] <file|folder>
            if cmd == "encrypt" && in_path == "-p" {
                let (len, path) = parse_len_and_path(&args[3..]);
                match path {
                    Some(p) => encrypt_with_password(len, p),
                    None => {
                        eprintln!("usage: enc encrypt -p [length] <file|folder>");
                        exit(1);
                    }
                }
                return;
            }
            let is_dir = if cmd == "encrypt-dir" {
                true
            } else {
                match fs::metadata(in_path) {
                    Ok(m) => m.is_dir(),
                    Err(e) => {
                        eprintln!("error: cannot read '{in_path}': {e}");
                        exit(1);
                    }
                }
            };
            let out_path = out_arg
                .map(str::to_string)
                .unwrap_or_else(|| default_enc_name(in_path));
            let (key, generated) = key_for_encrypt(&np_secret);

            let in_sz = path_size(Path::new(in_path));
            let t0 = Instant::now();
            let res = if is_dir {
                encrypt_dir(in_path, &key)
                    .and_then(|o| fs::write(&out_path, o).map_err(|e| e.to_string()))
            } else {
                fs::read(in_path)
                    .map_err(|e| e.to_string())
                    .and_then(|d| encrypt(&d, &key))
                    .and_then(|o| fs::write(&out_path, o).map_err(|e| e.to_string()))
            };
            let dur = t0.elapsed();
            if let Err(e) = res {
                eprintln!("error: {e}");
                exit(1);
            }

            let out_sz = fs::metadata(&out_path).map(|m| m.len()).unwrap_or(0);
            report("Encrypted", if is_dir { "folder" } else { "file" }, in_path, &out_path, in_sz, out_sz, dur);
            if let Some(hex_key) = generated {
                announce_key(&out_path, &hex_key);
            }
        }

        "decrypt" | "decrypt-dir" => {
            let blob = match fs::read(in_path) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("error: cannot read '{in_path}': {e}");
                    exit(1);
                }
            };
            let version = match peek_version(&blob) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("error: {e}");
                    exit(1);
                }
            };
            let in_sz = blob.len() as u64;
            let t0 = Instant::now();
            let fail = |e: &str| -> ! {
                eprintln!("{} {}", if color_enabled() { "\u{2717}" } else { "x" }, yellow(e));
                exit(1);
            };
            let (plain, integrity): (Vec<u8>, Option<String>) = if version == VERSION_PW {
                // Password mode: -np value, else ENC_PASS, else prompt.
                let pw = resolve_password(&np_secret);
                match decrypt_pw(&blob, &pw) {
                    Ok(p) => (p, None),
                    Err(e) => fail(&e),
                }
            } else {
                // Key mode: -np value, else ENC_KEY, else prompt.
                let key = resolve_key(&np_secret);
                match decrypt(&blob, &key) {
                    Ok(x) => x,
                    Err(e) => fail(&e),
                }
            };
            let as_dir = cmd == "decrypt-dir" || looks_like_tar(&plain);
            let out = out_arg
                .map(str::to_string)
                .unwrap_or_else(|| default_dec_base(in_path));
            let out_sz = plain.len() as u64;
            let res = if as_dir {
                unpack_tar(&plain, &out)
            } else {
                fs::write(&out, &plain).map_err(|e| e.to_string())
            };
            let dur = t0.elapsed();
            if let Err(e) = res {
                eprintln!("error: {e}");
                exit(1);
            }

            report("Decrypted", if as_dir { "folder" } else { "file" }, in_path, &out, in_sz, out_sz, dur);
            if let Some(sha) = integrity {
                let mark = if color_enabled() { "✓" } else { "OK" };
                eprintln!(
                    "   {}  {} {}",
                    dim(&format!("{:<7}", "sha256")),
                    green(&format!("{mark} verified")),
                    dim(&sha[..16])
                );
            }
        }

        other => {
            eprintln!("unknown command: {other}\n");
            print_help();
            exit(1);
        }
    }
}
