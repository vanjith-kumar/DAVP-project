#!/bin/bash
# SecureLog AI - Local Development Runner

set -e

export PATH="$HOME/.local/bin:$PATH"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$PROJECT_ROOT/backend"
FRONTEND_DIR="$PROJECT_ROOT/frontend"

echo "=========================================="
echo "    SecureLog AI - Local Host Launcher    "
echo "=========================================="

# 1. Setup Backend
echo ""
echo "[1/3] Setting up Python backend..."
cd "$BACKEND_DIR"

if [ ! -d "venv" ]; then
    echo "Creating Python virtual environment in backend/venv..."
    python3 -m venv venv
fi

source venv/bin/activate
echo "Installing backend dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Ensure .env exists in backend
if [ ! -f ".env" ]; then
    echo "Creating backend .env file..."
    cat <<EOT > .env
DATABASE_URL=sqlite+aiosqlite:///./securelog.db
SECRET_KEY=super-secret-key-change-for-production
SESSION_EXPIRE_MINUTES=1440
CORS_ORIGINS=http://localhost:5173,http://localhost
THREAT_INTEL_PROVIDER=mock
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=qwen2.5-coder:32b
EOT
fi

# Initialize database & seed admin user
echo "Initializing database & seeding default admin..."
python setup_db.py
python seed_admin.py || true
python seed_packets.py || true
python "$PROJECT_ROOT/scripts/generate_telemetry.py" || true

# 2. Check Frontend
echo ""
echo "[2/3] Checking Frontend..."
cd "$FRONTEND_DIR"
if command -v npm &> /dev/null; then
    echo "Installing frontend dependencies..."
    npm install
else
    echo "WARNING: Node.js / npm is not installed or not in PATH."
    echo "Please install Node.js (v18+) to run the frontend UI."
fi

echo ""
echo "=========================================="
echo "Setup complete! To run the application:"
echo ""
echo "TERMINAL 1 (Backend API):"
echo "  cd backend"
echo "  source venv/bin/activate"
echo "  uvicorn app.main:app --reload --port 8000"
echo ""
echo "TERMINAL 2 (Frontend Dashboard):"
echo "  cd frontend"
echo "  npm run dev"
echo ""
echo "URLs:"
echo "  Frontend Dashboard : http://localhost:5173"
echo "  Backend API Docs   : http://localhost:8000/docs"
echo "  Admin Login        : admin / admin123"
echo "=========================================="
