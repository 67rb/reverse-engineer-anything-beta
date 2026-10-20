#!/bin/zsh
set -e

APP_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"

if ! command -v node >/dev/null 2>&1; then
  echo "Node.js is not available. Install Node.js, then try again."
  read -r "?Press Return to close..."
  exit 1
fi

if ! command -v rea >/dev/null 2>&1; then
  echo "REA is not available on PATH. Open Terminal and run: rea --version"
  read -r "?Press Return to close..."
  exit 1
fi

cd "$APP_DIR"
node server.mjs --open
