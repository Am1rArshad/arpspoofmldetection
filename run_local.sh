#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
VENV_PYTHON="$ROOT_DIR/venv/bin/python"
FRONTEND_DIR="$ROOT_DIR/frontend"
DATA_DIR="$ROOT_DIR/data"

if [[ ! -x "$VENV_PYTHON" ]]; then
    echo "Python virtual environment not found. Create it with:"
    echo "  python3 -m venv venv"
    echo "  venv/bin/python -m pip install -r requirements.txt"
    exit 1
fi

if ! "$VENV_PYTHON" -c 'import pandas, joblib, sklearn, fastapi, uvicorn' 2>/dev/null; then
    echo "Python dependencies are missing. Install them with:"
    echo "  venv/bin/python -m pip install -r requirements.txt"
    exit 1
fi

if [[ "$EUID" -eq 0 ]]; then
    chown -R "${SUDO_USER:-root}:${SUDO_USER:-root}" "$DATA_DIR"
elif [[ ! -w "$DATA_DIR" || ! -w "$DATA_DIR/uploaded_dataset.csv" ]]; then
    if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
        echo "Fixing data directory permissions..."
        sudo chown -R "$USER":"$(id -gn)" "$DATA_DIR"
    else
        echo "Warning: sudo is unavailable or passwordless sudo is disabled. Continuing without data permission repair."
    fi
fi

if [[ ! -d "$FRONTEND_DIR/node_modules" ]] || ! (cd "$FRONTEND_DIR" && npm ls --depth=0 >/dev/null 2>&1); then
    echo "Installing frontend dependencies..."
    (cd "$FRONTEND_DIR" && npm install)
fi

pids=()
cleanup() {
    trap - TERM INT EXIT
    echo
    echo "Stopping IDS services..."
    for pid in "${pids[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
}
trap cleanup TERM INT EXIT

run_service() {
    local name="$1"
    shift
    echo "Starting $name..."
    "$@" &
    pids+=("$!")
}

cd "$ROOT_DIR"
run_service "backend" "$VENV_PYTHON" -m uvicorn backend.main:app --reload --port 8000
run_service "frontend" npm --prefix "$FRONTEND_DIR" run dev

if [[ "$EUID" -eq 0 ]]; then
    run_service "packet capture" "$VENV_PYTHON" "$ROOT_DIR/src/sniffer.py"
elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    run_service "packet capture" sudo -E "$VENV_PYTHON" "$ROOT_DIR/src/sniffer.py"
else
    echo
    echo "WARNING: Packet capture was skipped because sudo is unavailable or passwordless sudo is not configured."
    echo "         Live traffic monitoring will not run until you either:"
    echo "           1) run this script as root, or"
    echo "           2) enable passwordless sudo for your user."
    echo "         Backend and dashboard services will still start normally."
    echo
fi

run_service "real-time detection" "$VENV_PYTHON" "$ROOT_DIR/src/realtime_detect.py"

echo
if [[ "$EUID" -ne 0 ]] && ! (command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1); then
    echo "IDS is running with limited startup:
  Dashboard: http://localhost:5173
  Backend:   http://localhost:8000/docs
  Packet capture: skipped (sudo unavailable)
  Threat detection: running"
else
    echo "IDS is running:"
    echo "  Dashboard: http://localhost:5173"
    echo "  Backend:   http://localhost:8000/docs"
    echo "  Packet capture: active"
    echo "  Threat detection: running"
fi
echo "Press Ctrl+C to stop all services."

wait
