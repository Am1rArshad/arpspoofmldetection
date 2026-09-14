#!/bin/bash
set -e

# Start packet sniffer in background
python src/sniffer.py &

# Start real-time detection in background
python src/realtime_detect.py &

# Start the FastAPI backend, which serves the built React dashboard.
exec uvicorn backend.main:app --host 0.0.0.0 --port 8000