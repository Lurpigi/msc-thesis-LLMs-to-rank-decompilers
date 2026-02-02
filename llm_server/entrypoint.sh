#!/bin/bash
set -e

echo "[INIT] Starting container entrypoint..."

if command -v nvidia-smi &> /dev/null; then
    echo "[CHECK] Nvidia Driver found. GPU Status:"
    nvidia-smi --query-gpu=name,memory.total,memory.free --format=csv,noheader
else
    echo "[WARN] nvidia-smi not found. Running in CPU-only mode or Driver missing."
fi

echo "[INIT] Checking model cache..."
python3 -c "from app import download_all_models; download_all_models()"

# echo "[TEST] Running unit tests..."
# python3 -m unittest app.py

echo "[START] Starting Gunicorn WSGI Server..."
exec gunicorn --workers 1 \
              --threads 1 \
              --timeout 600 \
              --bind 0.0.0.0:8900 \
              --access-logfile - \
              --error-logfile - \
              app:app