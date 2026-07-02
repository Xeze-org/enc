#!/usr/bin/env bash
# enc installer for Linux / macOS
#
#   curl -fsSL https://raw.githubusercontent.com/Xeze-org/enc/main/install.sh | bash
#
# Downloads the latest enc binary and puts it on your PATH so `enc` works everywhere.
set -euo pipefail

repo="Xeze-org/enc"
bindir="${ENC_BINDIR:-$HOME/.local/bin}"

os="$(uname -s)"
arch="$(uname -m)"
case "$os-$arch" in
    Linux-x86_64)   asset="enc-linux-x86_64" ;;
    Linux-aarch64)  asset="enc-linux-aarch64" ;;
    Darwin-arm64)   asset="enc-macos-arm64" ;;
    Darwin-x86_64)  asset="enc-macos-x86_64" ;;
    *) echo "unsupported platform: $os-$arch" >&2; exit 1 ;;
esac

url="https://github.com/$repo/releases/latest/download/$asset"

echo "Downloading enc -> $bindir/enc"
mkdir -p "$bindir"
curl -fsSL "$url" -o "$bindir/enc"
chmod +x "$bindir/enc"

# Ensure the install dir is on PATH (add to shell rc files if missing)
case ":$PATH:" in
    *":$bindir:"*) ;;
    *)
        for rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
            if [ -f "$rc" ] && ! grep -qF "$bindir" "$rc"; then
                echo "export PATH=\"\$PATH:$bindir\"" >> "$rc"
            fi
        done
        echo "Added $bindir to PATH — restart your shell (or: export PATH=\"\$PATH:$bindir\")"
        ;;
esac

echo ""
echo "Done. Run:  enc help"
