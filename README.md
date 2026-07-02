# `enc`

![Release](https://img.shields.io/github/v/release/Xeze-org/enc?sort=semver)
![Build](https://img.shields.io/github/actions/workflow/status/Xeze-org/enc/release.yml)
![License](https://img.shields.io/github/license/Xeze-org/enc)
![Built with Rust](https://img.shields.io/badge/built_with-Rust-000000?logo=rust&logoColor=white)
![Crypto: AES-256-GCM](https://img.shields.io/badge/crypto-AES--256--GCM-4c1)
![Platforms](https://img.shields.io/badge/platforms-Windows_·_Linux_·_macOS-informational)

Encrypt any file or folder with **one small, dependency-free binary**.
AES-256-GCM. No runtime to install — just download and run.

## Install

**Windows** (PowerShell)
```powershell
irm https://raw.githubusercontent.com/Xeze-org/enc/main/install.ps1 | iex
```

**Linux / macOS**
```bash
curl -fsSL https://raw.githubusercontent.com/Xeze-org/enc/main/install.sh | bash
```

**Docker** (Alpine) — the Linux binary is static (musl), so it runs with no glibc
```dockerfile
RUN apk add --no-cache curl \
 && curl -fsSL https://raw.githubusercontent.com/Xeze-org/enc/main/install.sh | sh
ENV PATH="/root/.local/bin:${PATH}"
```

## Quick start

```bash
enc keygen              # make a key — SAVE the printed value
export ENC_KEY="<key>"  #  (PowerShell:  $env:ENC_KEY = "<key>")

enc diary.txt           # encrypt  ->  diary.txt.enc
enc diary.txt.enc       # decrypt  ->  diary.txt
enc Photos              # encrypt a whole folder
```

`enc <path>` figures out the direction from the file's **content**: plaintext →
encrypt, an `.enc` file → decrypt (it prompts for the key/password).

## Docs

- **[Usage & commands »](docs/USAGE.md)** — all modes, passwords, scripting, Docker, troubleshooting
- **[File format »](docs/FORMAT.md)** — the on-disk `.enc` layout and versions

## License

[Apache-2.0](LICENSE) © Xeze
