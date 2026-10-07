#!/usr/bin/env bash
# Start the FastAPI service (port 8000) and the Streamlit UI (port 8501).
set -e
cd "$(dirname "$0")/.."
export TARA_API_URL="${TARA_API_URL:-http://localhost:8000}"
uvicorn app.api:app --host 127.0.0.1 --port 8000 &
API_PID=$!
trap "kill $API_PID" EXIT
sleep 3
streamlit run ui/streamlit_app.py --server.port 8501 --server.address 127.0.0.1
