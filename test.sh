#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m pip check
if [ -d frontend/node_modules ]; then (cd frontend && npm run build); fi
