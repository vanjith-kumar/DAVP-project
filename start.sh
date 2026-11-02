#!/bin/bash
# SecureLog AI - One-Command Localhost Runner

set -e

export PATH="$HOME/.local/bin:$PATH"

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$PROJECT_DIR/backend"
FRONTEND_DIR="$PROJECT_DIR/frontend"

# Gracefully kill all background processes on exit (Ctrl+C)
cleanup() {
    echo ""
    echo "[*] Stopping backend and frontend..."
    kill $(jobs -p) 2>/dev/null || true
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

# 1. Backend Setup & Start
cd "$BACKEND_DIR"
if [ ! -d "venv" ]; then
    echo "[1/4] Setting up Python virtual environment..."
    python3 -m venv venv
fi
source venv/bin/activate

echo "[2/4] Installing backend dependencies..."
pip install -q -r requirements.txt

if [ ! -f "securelog.db" ]; then
    echo "[*] Initializing database and admin user..."
    python setup_db.py
    python seed_admin.py
    python seed_packets.py || true
    python "$PROJECT_DIR/scripts/generate_telemetry.py" || true
fi

echo "[3/4] Starting FastAPI backend on http://localhost:8000..."
uvicorn app.main:app --port 8000 &

# 2. Frontend Setup & Start
cd "$FRONTEND_DIR"
echo "[4/4] Starting Frontend UI..."
if command -v npm &> /dev/null; then
    if [ ! -d "node_modules" ]; then
        echo "[*] Installing frontend dependencies..."
        npm install
    fi
    npm run dev &
else
    echo "============================================================"
    echo "⚠️  Node.js / npm not found in your PATH."
    echo "   Backend is running, but please install Node.js (https://nodejs.org)"
    echo "   to run the frontend dashboard."
    echo "============================================================"
fi

echo ""
echo "=========================================================="
echo "🚀 SecureLog AI is now running on localhost!"
echo ""
echo "   📊 Frontend Dashboard : http://localhost:5173"
echo "   📖 Backend API (Docs) : http://localhost:8000/docs"
echo "   🔑 Default Login      : admin / admin123"
echo ""
echo "Press Ctrl+C to stop all services."
echo "=========================================================="

wait
