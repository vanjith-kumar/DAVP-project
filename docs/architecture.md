# Architecture

The system is built as a modular application with the following components:

## Phase 1 Components

- **Frontend**: React + TypeScript application built with Vite and Tailwind CSS. Acts as the presentation layer.
- **Backend**: FastAPI web framework serving REST endpoints.
- **Services**: Business logic decoupled from API routing.
- **Database**: PostgreSQL storing configuration, events, alerts, and users.

## Future Components

- **Ingestion Engine**: Real-time log collectors.
- **Detection Engine**: Rule-based detection against ingested events.
- **ML/AI Module**: Anomaly detection and LLM-powered incident explanations.
- **Threat Intelligence**: IP reputation enrichment.
