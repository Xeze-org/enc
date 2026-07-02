# Usage

[← back to README](../README.md)

## ⚠️ The one rule

`enc` is real encryption: **lose the key/password and the data is gone forever.**
Store it in a password manager (Bitwarden, 1Password, KeePass) — never next to
the `.enc` file.

---

## How `enc <path>` decides what to do

You don't type `encrypt` or `decrypt` — just point it at something:

```mermaid
flowchart TD
    A["enc PATH"] --> B{"Is it a folder?"}
    B -- yes --> ENCF["encrypt folder -> PATH.enc"]
    B -- no --> C{"First 4 bytes are ENC1?"}
    C -- "no, plaintext" --> ENC["encrypt file -> PATH.enc"]
    C -- "yes, encrypted" --> DEC["decrypt -> original file/folder"]
    DEC --> S["needs the key/password"]
```

It reads the file's **content**, not its name — so a rename never fools it.

---

## Command cheat sheet

| Command | What it does |
|---|---|
| `enc <path>` | Smart: encrypt if plaintext, decrypt if `.enc` |
| `enc keygen` | Make a reusable 32-byte key (prints it) |
| `enc -p [len]` | Generate a strong password |
| `enc -p [len] <path>` | Encrypt `<path>` with a generated password |
| `enc sha256 <file> [hash]` | Print a file's SHA-256, or verify it |
| `enc encrypt <path> [out]` | Explicit encrypt (file or folder) |
| `enc decrypt <file.enc> [dest]` | Explicit decrypt |
| `... -np <secret>` | Supply key/password inline (no prompt) — for scripts |

---

## Three ways to unlock

| Way | How | Best for |
|---|---|---|
| **Shared key** | set `ENC_KEY`, reuse for everything | your own quick use |
| **Per-file key** | *don't* set `ENC_KEY` → `enc` generates + prints one per file | isolating each file |
| **Password** | `enc -p [len] <path>` → generates a password | human-friendly secret |

### Where the secret comes from when decrypting

```mermaid
flowchart LR
    N{"-np given?"} -- yes --> U["use it"]
    N -- no --> E{"ENC_KEY / ENC_PASS set?"}
    E -- yes --> U
    E -- no --> T{"a real terminal?"}
    T -- yes --> P["prompt you (hidden)"]
    T -- no --> X["error (won't hang)"]
```

`enc` picks **key vs password automatically** from the file — you just supply
the secret.

---

## Password mode

```powershell
enc -p 30 diary.txt        # encrypt with a 30-char password (printed — save it!)
$env:ENC_PASS = "<that password>"
enc diary.txt.enc          # decrypts (auto-detects password files)
```

Uses **scrypt** + a random salt, so even a short password is hardened.

## Scripting (`-np`)

```powershell
enc secret.enc -np $secret     # no prompt, no env var; $secret = key OR password
```

> A secret on the command line can show in the process list / shell history.
> For sensitive automation, prefer `ENC_KEY` / `ENC_PASS`.

## Docker (Alpine)

The Linux binary is static (musl), so it runs on Alpine with no glibc:

```dockerfile
RUN apk add --no-cache curl \
 && curl -fsSL https://raw.githubusercontent.com/Xeze-org/enc/main/install.sh | sh
ENV PATH="/root/.local/bin:${PATH}"
```

Then `enc /app` encrypts your app directory into `/app.enc`, and
`ENC_PASS=... enc /app.enc` (or a key) restores it at startup.

---

## ✅ Safe workflow (until you trust it)

Prove you can get data back **before** deleting the original:

```powershell
enc important                      # -> important.enc
enc important.enc  test-restore    # decrypt to a test folder
#  compare, e.g. (Git Bash):  diff -r important test-restore
#  only then delete the original
```

The `.enc` file is safe to store anywhere (cloud, USB, email) — meaningless
without the key. Just don't store the key beside it.

---

## Troubleshooting

| Message | Meaning |
|---|---|
| `key required: set ENC_KEY or pass -np` | No key available and no terminal to prompt |
| `wrong password or corrupted file` | Bad password, or the file was altered |
| `message authentication failed` | Wrong key, or the `.enc` file was altered |
| `bad magic (not an enc file)` | The input isn't an `enc` file |

**Good to know:** encrypting the same thing twice gives different bytes (random
IV — normal); a tampered `.enc` refuses to decrypt (GCM checks integrity); the
`.enc` is ~33 bytes larger than the original (+ a little for folders).
