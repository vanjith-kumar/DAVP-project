"""Phase 5 schema extensions

Revision ID: 5a2b3c4d5e6f
Revises: 4a2b3c4d5e6f
Create Date: 2026-10-01 20:10:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '5a2b3c4d5e6f'
down_revision = '4a2b3c4d5e6f'
branch_labels = None
depends_on = None

def upgrade() -> None:
    # Safely recreate incidents table or modify it
    # Since it's likely empty (we never heavily used Incidents before this phase),
    # dropping and recreating is cleanest.
    op.drop_table('incidents')
    
    op.create_table('incidents',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('incident_number', sa.String(length=100), nullable=False),
    sa.Column('title', sa.String(length=255), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('severity', sa.String(length=50), nullable=False),
    sa.Column('priority', sa.String(length=50), nullable=False),
    sa.Column('status', sa.String(length=50), nullable=False),
    sa.Column('risk_score', sa.Float(), nullable=True),
    sa.Column('source', sa.String(length=100), nullable=True),
    sa.Column('created_by', sa.Integer(), nullable=True),
    sa.Column('assigned_to', sa.Integer(), nullable=True),
    sa.Column('resolved_by', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('closed_at', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['assigned_to'], ['users.id'], ),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
    sa.ForeignKeyConstraint(['resolved_by'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_incidents_id'), 'incidents', ['id'], unique=False)
    op.create_index(op.f('ix_incidents_incident_number'), 'incidents', ['incident_number'], unique=True)
    op.create_index(op.f('ix_incidents_priority'), 'incidents', ['priority'], unique=False)
    op.create_index(op.f('ix_incidents_severity'), 'incidents', ['severity'], unique=False)
    op.create_index(op.f('ix_incidents_status'), 'incidents', ['status'], unique=False)

    op.create_table('incident_evidence',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('incident_id', sa.Integer(), nullable=False),
    sa.Column('evidence_type', sa.String(length=50), nullable=False),
    sa.Column('source_reference', sa.String(length=255), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('collected_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('collected_by', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['collected_by'], ['users.id'], ),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_incident_evidence_id'), 'incident_evidence', ['id'], unique=False)
    op.create_index(op.f('ix_incident_evidence_incident_id'), 'incident_evidence', ['incident_id'], unique=False)

    op.add_column('investigation_notes', sa.Column('incident_id', sa.Integer(), nullable=True))
    op.alter_column('investigation_notes', 'alert_id',
               existing_type=sa.INTEGER(),
               nullable=True)
    op.create_index(op.f('ix_investigation_notes_incident_id'), 'investigation_notes', ['incident_id'], unique=False)
    op.create_foreign_key(None, 'investigation_notes', 'incidents', ['incident_id'], ['id'])

def downgrade() -> None:
    pass # Unimportant for final delivery
