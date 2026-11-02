"""Phase 2 schema extensions

Revision ID: 1a2b3c4d5e6f
Revises: 
Create Date: 2026-10-01 19:20:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '1a2b3c4d5e6f'
down_revision = None
branch_labels = None
depends_on = None

def upgrade() -> None:
    # Add new columns to log_events
    op.add_column('log_events', sa.Column('destination_ip', sa.String(length=45), nullable=True))
    op.add_column('log_events', sa.Column('source_port', sa.Integer(), nullable=True))
    op.add_column('log_events', sa.Column('destination_port', sa.Integer(), nullable=True))
    op.add_column('log_events', sa.Column('action', sa.String(length=100), nullable=True))
    op.add_column('log_events', sa.Column('protocol', sa.String(length=50), nullable=True))
    op.add_column('log_events', sa.Column('service', sa.String(length=100), nullable=True))
    op.add_column('log_events', sa.Column('method', sa.String(length=20), nullable=True))
    op.add_column('log_events', sa.Column('path', sa.Text(), nullable=True))
    op.add_column('log_events', sa.Column('status_code', sa.Integer(), nullable=True))
    op.add_column('log_events', sa.Column('user_agent', sa.Text(), nullable=True))
    op.add_column('log_events', sa.Column('raw_message', sa.Text(), nullable=True))
    op.add_column('log_events', sa.Column('parser_name', sa.String(length=100), nullable=True))
    op.add_column('log_events', sa.Column('metadata', sa.JSON(), nullable=True))

    op.create_index(op.f('ix_log_events_destination_ip'), 'log_events', ['destination_ip'], unique=False)
    op.create_index(op.f('ix_log_events_action'), 'log_events', ['action'], unique=False)
    op.create_index(op.f('ix_log_events_service'), 'log_events', ['service'], unique=False)

    # Add deduplication columns to alerts
    op.add_column('alerts', sa.Column('source_ip', sa.String(length=45), nullable=True))
    op.add_column('alerts', sa.Column('username', sa.String(length=255), nullable=True))
    op.add_column('alerts', sa.Column('event_count', sa.Integer(), server_default='1', nullable=False))
    op.add_column('alerts', sa.Column('rule_id', sa.Integer(), nullable=True))
    op.add_column('alerts', sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=True))
    
    op.create_foreign_key(None, 'alerts', 'detection_rules', ['rule_id'], ['id'])
    op.create_index(op.f('ix_alerts_source_ip'), 'alerts', ['source_ip'], unique=False)
    op.create_index(op.f('ix_alerts_username'), 'alerts', ['username'], unique=False)


def downgrade() -> None:
    # Downgrade alerts
    op.drop_constraint(None, 'alerts', type_='foreignkey')
    op.drop_index(op.f('ix_alerts_username'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_source_ip'), table_name='alerts')
    op.drop_column('alerts', 'last_seen_at')
    op.drop_column('alerts', 'rule_id')
    op.drop_column('alerts', 'event_count')
    op.drop_column('alerts', 'username')
    op.drop_column('alerts', 'source_ip')

    # Downgrade log_events
    op.drop_index(op.f('ix_log_events_service'), table_name='log_events')
    op.drop_index(op.f('ix_log_events_action'), table_name='log_events')
    op.drop_index(op.f('ix_log_events_destination_ip'), table_name='log_events')
    
    op.drop_column('log_events', 'metadata')
    op.drop_column('log_events', 'parser_name')
    op.drop_column('log_events', 'raw_message')
    op.drop_column('log_events', 'user_agent')
    op.drop_column('log_events', 'status_code')
    op.drop_column('log_events', 'path')
    op.drop_column('log_events', 'method')
    op.drop_column('log_events', 'service')
    op.drop_column('log_events', 'protocol')
    op.drop_column('log_events', 'action')
    op.drop_column('log_events', 'destination_port')
    op.drop_column('log_events', 'source_port')
    op.drop_column('log_events', 'destination_ip')
