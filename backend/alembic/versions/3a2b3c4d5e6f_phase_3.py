"""Phase 3 schema extensions

Revision ID: 3a2b3c4d5e6f
Revises: 1a2b3c4d5e6f
Create Date: 2026-10-01 19:24:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '3a2b3c4d5e6f'
down_revision = '1a2b3c4d5e6f'
branch_labels = None
depends_on = None

def upgrade() -> None:
    # Create MLModels
    op.create_table('ml_models',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('model_type', sa.String(length=100), nullable=False),
    sa.Column('model_version', sa.String(length=50), nullable=False),
    sa.Column('status', sa.String(length=50), nullable=False),
    sa.Column('feature_version', sa.String(length=50), nullable=False),
    sa.Column('window_size', sa.Integer(), nullable=True),
    sa.Column('parameters', sa.JSON(), nullable=True),
    sa.Column('training_event_count', sa.Integer(), nullable=False),
    sa.Column('trained_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('path', sa.String(length=255), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_ml_models_id'), 'ml_models', ['id'], unique=False)
    op.create_index(op.f('ix_ml_models_model_version'), 'ml_models', ['model_version'], unique=True)

    # Create ThreatIntelCache
    op.create_table('threat_intel_cache',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('ip_address', sa.String(length=45), nullable=False),
    sa.Column('provider', sa.String(length=100), nullable=False),
    sa.Column('result', sa.JSON(), nullable=False),
    sa.Column('lookup_timestamp', sa.DateTime(timezone=True), nullable=False),
    sa.Column('expiration', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_threat_intel_cache_id'), 'threat_intel_cache', ['id'], unique=False)
    op.create_index(op.f('ix_threat_intel_cache_ip_address'), 'threat_intel_cache', ['ip_address'], unique=True)

    # Create AIExplanations
    op.create_table('ai_explanations',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('alert_id', sa.Integer(), nullable=False),
    sa.Column('model_name', sa.String(length=100), nullable=False),
    sa.Column('prompt_version', sa.String(length=100), nullable=False),
    sa.Column('summary', sa.Text(), nullable=False),
    sa.Column('explanation', sa.JSON(), nullable=False),
    sa.Column('confidence', sa.String(length=50), nullable=False),
    sa.Column('generation_status', sa.String(length=50), nullable=False),
    sa.Column('generated_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['alert_id'], ['alerts.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('alert_id')
    )
    op.create_index(op.f('ix_ai_explanations_id'), 'ai_explanations', ['id'], unique=False)

def downgrade() -> None:
    op.drop_index(op.f('ix_ai_explanations_id'), table_name='ai_explanations')
    op.drop_table('ai_explanations')
    op.drop_index(op.f('ix_threat_intel_cache_ip_address'), table_name='threat_intel_cache')
    op.drop_index(op.f('ix_threat_intel_cache_id'), table_name='threat_intel_cache')
    op.drop_table('threat_intel_cache')
    op.drop_index(op.f('ix_ml_models_model_version'), table_name='ml_models')
    op.drop_index(op.f('ix_ml_models_id'), table_name='ml_models')
    op.drop_table('ml_models')
