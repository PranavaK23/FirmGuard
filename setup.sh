#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
python3 -m venv .venv
.venv/bin/python -m pip install -r backend/requirements-lock.txt
if [ "${1:-}" = "--rebuild-frontend" ] || [ ! -f frontend/dist/index.html ]; then
  (cd frontend && npm ci && npm run build)
fi
printf '%s\n' 'Setup complete. Run sh start.sh and open http://127.0.0.1:8000.'
