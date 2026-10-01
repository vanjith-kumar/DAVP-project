# SecureLog AI

## Real-Time AI-Powered Security Log Monitoring, Anomaly Detection & Incident Analysis Platform

SecureLog AI is a web-based cybersecurity monitoring platform designed to ingest system/application logs, detect suspicious activity, and provide AI-driven incident analysis.

### Phase 1 Features
Currently implemented (Phase 1):
- FastAPI Backend Foundation with PostgreSQL and SQLAlchemy 2.x
- Authentication (JWT + Argon2) and Role-Based Access Control (RBAC) foundation
- Alembic database migrations
- React + Vite + Tailwind CSS Frontend Shell
- Centralized configuration system (`.env`)
- Docker compose development environment setup
- Pytest test foundation

*Planned for later phases:* Real-time log collection, AI/ML detection modules, WebSockets, full incident response workflow.

### Requirements
- Docker and Docker Compose
- Node.js 20+ (for local frontend dev)
- Python 3.12+ (for local backend dev)

### Installation & Environment Configuration
1. Clone this repository.
2. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```

### Running the application with Docker
We provide a `docker-compose.yml` for local development.

1. Start the database, backend, and frontend:
   ```bash
   docker-compose up --build -d
   ```
2. The frontend is accessible at http://localhost:5173
3. The backend API is accessible at http://localhost:8000

### Database Setup
To initialize the database tables, run the Alembic migrations from within the backend container:
```bash
docker-compose exec backend alembic upgrade head
```

### Testing
To run tests:
```bash
docker-compose exec backend pytest
```

### Project Structure
- `/backend`: FastAPI Python application
- `/frontend`: React + TypeScript frontend
- `/docs`: Architecture and database documentation
- `/sample_logs`: Directory for test data
