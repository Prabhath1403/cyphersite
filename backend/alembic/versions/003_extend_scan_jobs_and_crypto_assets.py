"""Extend scan_jobs and crypto_assets tables

Revision ID: 003
Revises: 002
Create Date: 2026-09-10
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = '003'
down_revision: Union[str, None] = '002'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add scan_type to scan_jobs
    op.add_column(
        'scan_jobs',
        sa.Column('scan_type', sa.String(50), nullable=False, server_default='network')
    )

    # Add extended columns to crypto_assets
    op.add_column('crypto_assets', sa.Column('primitive', sa.String(50), nullable=True))
    op.add_column('crypto_assets', sa.Column('mode', sa.String(30), nullable=True))
    op.add_column('crypto_assets', sa.Column('padding', sa.String(30), nullable=True))
    op.add_column('crypto_assets', sa.Column('usage', sa.String(50), nullable=True))
    op.add_column('crypto_assets', sa.Column('repository', sa.String(500), nullable=True))
    op.add_column('crypto_assets', sa.Column('confidence', sa.Float(), nullable=True))
    op.add_column('crypto_assets', sa.Column('evidence', postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column('crypto_assets', sa.Column('quantum_status', sa.String(30), nullable=True))
    op.add_column('crypto_assets', sa.Column('risk_level', sa.String(10), nullable=True))
    op.add_column('crypto_assets', sa.Column('sensitivity', sa.String(30), nullable=True))
    op.add_column('crypto_assets', sa.Column('sensitivity_confidence', sa.Float(), nullable=True))


def downgrade() -> None:
    op.drop_column('crypto_assets', 'sensitivity_confidence')
    op.drop_column('crypto_assets', 'sensitivity')
    op.drop_column('crypto_assets', 'risk_level')
    op.drop_column('crypto_assets', 'quantum_status')
    op.drop_column('crypto_assets', 'evidence')
    op.drop_column('crypto_assets', 'confidence')
    op.drop_column('crypto_assets', 'repository')
    op.drop_column('crypto_assets', 'usage')
    op.drop_column('crypto_assets', 'padding')
    op.drop_column('crypto_assets', 'mode')
    op.drop_column('crypto_assets', 'primitive')
    op.drop_column('scan_jobs', 'scan_type')
