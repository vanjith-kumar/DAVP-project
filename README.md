# SecureLog AI

**Real-Time AI-Powered Security Log Monitoring, Anomaly Detection & Incident Analysis Platform**

SecureLog AI is an enterprise-grade cybersecurity operations platform designed to turn raw security logs and network packets into actionable, explainable, and auditable investigations while keeping high-impact decisions under human control.

It combines deterministic security rules, behavioral machine learning, threat intelligence, and local LLM integration to build a complete SOC Analyst Workspace.

---

## Project Structure

The repository is organized following clean, professional software engineering practices:

```text
securelog-ai/
├── backend/                       # FastAPI Backend Application
│   ├── alembic/                   # Database schema migrations
│   ├── app/                       # Application source code
│   │   ├── ai/                    # Local LLM explanation & safety sanitization
│   │   ├── api/                   # REST API routes (dashboard, alerts, logs, packets...)
│   │   ├── core/                  # Configuration, security, permissions & JWT auth
│   │   ├── database/              # SQLAlchemy models and session management
│   │   ├── detection/             # Rule matcher and correlation engine
│   │   ├── ingestion/             # Multi-format parsers (Windows, Apache, Syslog...)
│   │   ├── ml/                    # Scikit-Learn Isolation Forest anomaly detection
│   │   ├── realtime/              # WebSocket manager for live log streaming
│   │   ├── reports/               # Automated PDF and CSV report generators
│   │   ├── schemas/               # Pydantic validation schemas
│   │   ├── services/              # Business logic & data access services
│   │   └── threat_intel/          # AbuseIPDB integration & local reputation cache
│   ├── data/                      # Backend PCAP captures and runtime datasets
│   ├── tests/                     # Automated Pytest suite (API, detection, ML, parsers)
│   ├── Dockerfile                 # Backend container definition
│   ├── pytest.ini                 # Pytest configuration
│   ├── requirements.txt           # Python package dependencies
│   └── securelog.db               # SQLite local database (or PostgreSQL in Docker)
│
├── frontend/                      # React 19 + TypeScript + Vite UI
│   ├── src/                       # Application source code
│   │   ├── assets/                # Static icons, logos, and graphic assets
│   │   ├── components/            # Reusable UI widgets and navigation layout
│   │   ├── hooks/                 # Custom React hooks (realtime WebSocket stream)
│   │   ├── pages/                 # Full SOC Views: Dashboard, Alerts, Logs, Incidents, Packets
│   │   └── services/              # Axios HTTP API client
│   ├── public/                    # Public static web assets
│   ├── Dockerfile                 # Multi-stage production container build
│   └── package.json               # Node.js dependencies and build scripts
│
├── data/                          # Centralized Data & Log Samples
│   ├── dashboard_mock_logs.csv    # 24-hour synthetic security telemetry dataset
│   ├── mock_logs.csv              # Raw sample syslog messages
│   └── samples/                   # Sample log files (Apache, Auth, Syslog, Windows)
│
├── scripts/                       # Developer & Operational Tooling
│   ├── generate_telemetry.py      # Statistical log generator, analysis & visualizer
│   ├── analyze_logs.py            # Python CLI tool for log statistics and chart plotting
│   ├── seed_mock_logs.py          # API batch ingestion utility
│   └── seed_rich_data.py          # Database trend population utility
│
├── docs/                          # Technical Documentation & Assets
│   ├── images/                    # SOC telemetry charts & visual diagrams
│   ├── architecture.md            # System design and component interactions
│   ├── database.md                # Entity relationship model and schemas
│   └── development.md             # Developer setup and contributor guide
│
├── docker-compose.yml             # Docker Compose multi-service orchestration
├── start.sh                       # One-command development runner (Ctrl+C to stop)
├── run_local.sh                   # Environment setup & launcher script
├── .env.example                   # Environment variable template
└── README.md                      # Project documentation
```

---

## Key Features

- **Real-Time SOC Dashboard**: High-resolution metrics, 24-hour activity timeline, severity donut, threat velocity, and top hostile sources powered by `Recharts`.
- **Packet Analyzer**: Deep packet inspection (.pcap and .csv) with hex dumps, protocol breakdowns, and network conversation graphs.
- **Rule-Based Threat Detection**: Deterministic alert rules for brute force, SQL injection, port scanning, and privilege escalation.
- **Behavioral Anomaly Detection**: `Isolation Forest` machine learning flagging abnormal volumetric and behavioral deviations.
- **Threat Intelligence**: IP reputation checks against `AbuseIPDB` and local threat caches.
- **AI Security Explanations**: Local `Ollama` LLM integration with automated log sanitization preventing credential exposure or prompt injection.
- **Incident Management**: Incident workflows with severity tagging, analyst notes, and downloadable PDF/CSV audit reports.

---

## Quick Start

### Option A: Localhost (Recommended for Development)

Prerequisites: Python 3.9+ and Node.js v18+.

Simply run the unified startup script:
```bash
./start.sh
```

This will automatically:
1. Initialize the Python virtual environment and install backend dependencies.
2. Initialize and seed the SQLite database with default admin credentials and telemetry.
3. Install frontend dependencies and launch the Vite development server.
4. Launch the FastAPI backend on `http://localhost:8000`.

**Access Links:**
- **Frontend Dashboard:** [http://localhost:5173](http://localhost:5173)
- **Backend API & Swagger Docs:** [http://localhost:8000/docs](http://localhost:8000/docs)
- **Default Credentials:** `admin` / `admin123`

---

### Option B: Docker Compose

```bash
cp .env.example .env
docker-compose up -d --build
```

---

## Data Analysis & Telemetry Scripts

A suite of Python data analysis and visualization tools are included in `scripts/`:

```bash
# 1. Analyze any security log CSV file and print summary metrics:
backend/venv/bin/python scripts/analyze_logs.py --file data/dashboard_mock_logs.csv

# 2. Analyze and generate a dual-panel visualization chart:
backend/venv/bin/python scripts/analyze_logs.py --file data/dashboard_mock_logs.csv --plot docs/images/quick_analysis.png

# 3. Generate a fresh 24-hour synthetic attack telemetry dataset, perform Pandas analysis, render 6-panel Matplotlib charts, and seed database:
backend/venv/bin/python scripts/generate_telemetry.py
```

---

## Testing & Quality Assurance

### Backend Test Suite
Run the automated pytest test suite covering API endpoints, rule matching, ML feature extraction, and threat intelligence:
```bash
cd backend
venv/bin/pytest tests/
```

### Frontend Typecheck & Build
```bash
cd frontend
npm run build
```

---

## Security Best Practices
- **Strict Data Sanitization**: Sensitive authentication tokens, passwords, and PII are redacted before data reaches AI models.
- **Human-in-the-Loop**: The platform provides actionable recommendations; high-impact incident resolutions remain under explicit analyst control.
