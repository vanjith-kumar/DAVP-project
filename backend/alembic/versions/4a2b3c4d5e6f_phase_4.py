"""Phase 4 schema extensions

Revision ID: 4a2b3c4d5e6f
Revises: 3a2b3c4d5e6f
Create Date: 2026-10-01 19:35:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '4a2b3c4d5e6f'
down_revision = '3a2b3c4d5e6f'
branch_labels = None
depends_on = None

def upgrade() -> None:
    # Add risk_score to alerts
    op.add_column('alerts', sa.Column('risk_score', sa.Float(), nullable=True))
    op.create_index(op.f('ix_alerts_risk_score'), 'alerts', ['risk_score'], unique=False)

    # Create investigation_notes table
    op.create_table('investigation_notes',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('alert_id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('note_text', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['alert_id'], ['alerts.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_investigation_notes_alert_id'), 'investigation_notes', ['alert_id'], unique=False)
    op.create_index(op.f('ix_investigation_notes_id'), 'investigation_notes', ['id'], unique=False)

def downgrade() -> None:
    op.drop_index(op.f('ix_investigation_notes_id'), table_name='investigation_notes')
    op.drop_index(op.f('ix_investigation_notes_alert_id'), table_name='investigation_notes')
    op.drop_table('investigation_notes')
    
    op.drop_index(op.f('ix_alerts_risk_score'), table_name='alerts')
    op.drop_column('alerts', 'risk_score')
