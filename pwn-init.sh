#!/usr/bin/env bash
set -euo pipefail
if ! command -v python3 >/dev/null 2>&1; then
    echo '[-] 需要 Python 3.9+，Ubuntu 可執行：sudo apt install python3' >&2
    exit 1
fi
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/pwn_init.py" "$@"
