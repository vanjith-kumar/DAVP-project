# Database Architecture

Built with PostgreSQL and SQLAlchemy ORM.

## Tables

- **users**: Accounts for access control (Admin, Analyst).
- **log_sources**: Configuration for systems sending logs.
- **log_events**: Parsed individual log entries.
- **detection_rules**: Configuration for rule-based security alerts.
- **alerts**: Generated when events match detection rules.
- **incidents**: Grouped alerts managed by analysts.
- **audit_logs**: Audit trail for critical actions.

## Relationships

- `User` creates `LogSource`.
- `LogSource` produces `LogEvent`.
- `Alerts` are assigned to `User`.
- `Incidents` are owned by `User`.
