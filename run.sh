#!/usr/bin/env bash
# Sentinel — one-command local run (no Docker required).
#   ./run.sh            start backend + frontend (API mode)
#   ./run.sh train      (re)train the world model + baseline
#   ./run.sh test       run the Python test suite
set -euo pipefail
cd "$(dirname "$0")"

setup_py() {
  [ -d .venv ] || python3 -m venv .venv
  # shellcheck disable=SC1091
  . .venv/bin/activate
  python -m pip install -q --upgrade pip
  python -m pip install -q -r requirements.txt
}

case "${1:-run}" in
  train)
    setup_py; python train.py ;;
  test)
    setup_py; python -m pytest -q ;;
  bench)
    setup_py; python benchmark.py ;;
  run)
    setup_py
    [ -f models/world_model.npz ] || python train.py
    echo "→ starting backend on :8000"
    uvicorn backend.main:app --host 0.0.0.0 --port 8000 &
    BACK=$!
    trap 'kill $BACK 2>/dev/null || true' EXIT
    command -v npm >/dev/null || { echo "npm required for the dashboard"; wait $BACK; }
    [ -d node_modules ] || npm install
    echo "→ starting dashboard on :3000 (API mode)"
    NEXT_PUBLIC_API_URL=http://localhost:8000 npm run dev
    ;;
  *)
    echo "usage: ./run.sh [run|train|test|bench]"; exit 1 ;;
esac
