# Development Guide

## Environment Setup
Make sure to copy `.env.example` to `.env`. This provides sensible defaults for local development.

## Docker Development
The primary development mechanism is Docker Compose.
Start the stack with:
```bash
docker-compose up --build
```

## Migrations
Alembic is used for database migrations. To create a new migration after modifying models:
```bash
docker-compose exec backend alembic revision --autogenerate -m "description"
```
Apply migrations:
```bash
docker-compose exec backend alembic upgrade head
```

## Testing
We use `pytest` for testing the backend.
```bash
docker-compose exec backend pytest
```
Tests use an in-memory SQLite database to avoid modifying production data.
