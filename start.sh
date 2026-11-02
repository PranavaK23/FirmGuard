#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
test -x .venv/bin/python || { printf '%s\n' 'Run sh setup.sh first.'; exit 1; }
test -f frontend/dist/index.html || { printf '%s\n' 'Build the interface first.'; exit 1; }
exec .venv/bin/python -m uvicorn main:app --app-dir backend --host 127.0.0.1 --port 8000 --workers 1
