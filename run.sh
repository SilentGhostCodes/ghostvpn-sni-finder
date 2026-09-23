#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 is required. Ubuntu: sudo apt install python3" >&2
  exit 1
fi
exec python3 ./reality_sni_finder.py "$@"
