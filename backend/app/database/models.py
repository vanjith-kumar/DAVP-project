from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import String, Boolean, DateTime, ForeignKey, Text, Enum, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
import enum

from app.database.base import Base

class RoleEnum(str, enum.Enum):
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"

def utcnow():
    return datetime.now(timezone.utc)

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[RoleEnum] = mapped_column(Enum(RoleEnum), default=RoleEnum.ANALYST)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

class LogSource(Base):
    __tablename__ = "log_sources"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(100), index=True)
    source_type: Mapped[str] = mapped_column(String(50))
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    configuration: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    created_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

class LogEvent(Base):
    __tablename__ = "log_events"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    source_id: Mapped[Optional[int]] = mapped_column(ForeignKey("log_sources.id"), index=True, nullable=True)
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    host: Mapped[Optional[str]] = mapped_column(String(255), index=True, nullable=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), index=True, nullable=True)
    destination_ip: Mapped[Optional[str]] = mapped_column(String(45), index=True, nullable=True)
    source_port: Mapped[Optional[int]] = mapped_column(nullable=True)
    destination_port: Mapped[Optional[int]] = mapped_column(nullable=True)
    username: Mapped[Optional[str]] = mapped_column(String(255), index=True, nullable=True)
    event_type: Mapped[Optional[str]] = mapped_column(String(100), index=True, nullable=True)
    action: Mapped[Optional[str]] = mapped_column(String(100), index=True, nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    service: Mapped[Optional[str]] = mapped_column(String(100), index=True, nullable=True)
    method: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status_code: Mapped[Optional[int]] = mapped_column(nullable=True)
    severity: Mapped[Optional[str]] = mapped_column(String(50), index=True, nullable=True)
    message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    raw_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    parser_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    parse_status: Mapped[str] = mapped_column(String(50), default="UNPARSED")
    metadata_: Mapped[Optional[dict]] = mapped_column("metadata", JSON, nullable=True)

class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    rule_type: Mapped[str] = mapped_column(String(50))
    configuration: Mapped[dict] = mapped_column(JSON)
    severity: Mapped[str] = mapped_column(String(50))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    version: Mapped[int] = mapped_column(default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(50), index=True)
    status: Mapped[str] = mapped_column(String(50), default="NEW", index=True)
    detection_type: Mapped[str] = mapped_column(String(100))
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), index=True, nullable=True)
    username: Mapped[Optional[str]] = mapped_column(String(255), index=True, nullable=True)
    event_count: Mapped[int] = mapped_column(default=1)
    rule_id: Mapped[Optional[int]] = mapped_column(ForeignKey("detection_rules.id"), nullable=True)
    assigned_to: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), default=utcnow)
    risk_score: Mapped[Optional[float]] = mapped_column(nullable=True, index=True)

class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    incident_number: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(50), index=True)
    priority: Mapped[str] = mapped_column(String(50), index=True)
    status: Mapped[str] = mapped_column(String(50), default="NEW", index=True)
    risk_score: Mapped[Optional[float]] = mapped_column(nullable=True)
    source: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    
    created_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    assigned_to: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    resolved_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

class IncidentEvidence(Base):
    __tablename__ = "incident_evidence"
    
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    evidence_type: Mapped[str] = mapped_column(String(50)) # e.g. ALERT, EVENT, IP, ML
    source_reference: Mapped[str] = mapped_column(String(255)) # e.g. alert_id
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    collected_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)

class InvestigationNote(Base):
    __tablename__ = "investigation_notes"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    alert_id: Mapped[Optional[int]] = mapped_column(ForeignKey("alerts.id"), index=True, nullable=True)
    incident_id: Mapped[Optional[int]] = mapped_column(ForeignKey("incidents.id"), index=True, nullable=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    note_text: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    actor_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(100), index=True)
    target_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    target_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    metadata_: Mapped[Optional[dict]] = mapped_column("metadata", JSON, nullable=True)

class MLModel(Base):
    __tablename__ = "ml_models"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    model_type: Mapped[str] = mapped_column(String(100))
    model_version: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(50))
    feature_version: Mapped[str] = mapped_column(String(50))
    window_size: Mapped[int] = mapped_column(nullable=True)
    parameters: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    training_event_count: Mapped[int] = mapped_column(default=0)
    trained_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    path: Mapped[str] = mapped_column(String(255))

class ThreatIntelCache(Base):
    __tablename__ = "threat_intel_cache"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    ip_address: Mapped[str] = mapped_column(String(45), index=True, unique=True)
    provider: Mapped[str] = mapped_column(String(100))
    result: Mapped[dict] = mapped_column(JSON)
    lookup_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expiration: Mapped[datetime] = mapped_column(DateTime(timezone=True))

class AIExplanation(Base):
    __tablename__ = "ai_explanations"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"), unique=True)
    model_name: Mapped[str] = mapped_column(String(100))
    prompt_version: Mapped[str] = mapped_column(String(100))
    summary: Mapped[str] = mapped_column(Text)
    explanation: Mapped[dict] = mapped_column(JSON)
    confidence: Mapped[str] = mapped_column(String(50))
    generation_status: Mapped[str] = mapped_column(String(50))
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
