"""Add crypto_assets table

Revision ID: 002
Revises: 001
Create Date: 2025-09-08
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = '002'
down_revision: Union[str, None] = '001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'crypto_assets',
        # Identity
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('scan_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('scan_jobs.id'), nullable=False),
        sa.Column('asset_type', sa.String(30), nullable=False),
        sa.Column('source_type', sa.String(20), nullable=False),
        sa.Column('name', sa.String(500), nullable=False),
        sa.Column('version', sa.String(100), nullable=True),

        # Cryptographic properties
        sa.Column('algorithm', sa.String(100), nullable=True),
        sa.Column('algorithm_family', sa.String(50), nullable=True),
        sa.Column('key_size', sa.Integer, nullable=True),
        sa.Column('key_type', sa.String(50), nullable=True),
        sa.Column('hash_algorithm', sa.String(50), nullable=True),
        sa.Column('key_exchange', sa.String(100), nullable=True),
        sa.Column('cipher_suite', sa.String(200), nullable=True),
        sa.Column('protocol', sa.String(50), nullable=True),

        # Library properties
        sa.Column('library', sa.String(200), nullable=True),
        sa.Column('library_version', sa.String(100), nullable=True),

        # Source-code provenance
        sa.Column('source_location', sa.String(500), nullable=True),
        sa.Column('file_path', sa.String(500), nullable=True),
        sa.Column('line_number', sa.Integer, nullable=True),
        sa.Column('function_name', sa.String(200), nullable=True),
        sa.Column('language', sa.String(50), nullable=True),

        # Network information
        sa.Column('hostname', sa.String(500), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('port', sa.Integer, nullable=True),

        # Security / PQC
        sa.Column('pqc_status', sa.String(20), nullable=True),
        sa.Column('risk_score', sa.Float, nullable=True),
        sa.Column('vulnerabilities', postgresql.JSONB, nullable=True),
        sa.Column('recommendations', postgresql.JSONB, nullable=True),

        # Future business-risk fields
        sa.Column('business_criticality', sa.String(20), nullable=True),
        sa.Column('data_sensitivity', sa.String(20), nullable=True),
        sa.Column('data_lifetime_years', sa.Integer, nullable=True),
        sa.Column('migration_time_months', sa.Integer, nullable=True),

        # Metadata
        sa.Column('details', postgresql.JSONB, nullable=True),
        sa.Column('created_at', sa.DateTime, nullable=False),
    )

    # Indexes for common filter/query patterns
    op.create_index('ix_crypto_assets_scan_id', 'crypto_assets', ['scan_id'])
    op.create_index('ix_crypto_assets_asset_type', 'crypto_assets', ['asset_type'])
    op.create_index('ix_crypto_assets_source_type', 'crypto_assets', ['source_type'])
    op.create_index('ix_crypto_assets_pqc_status', 'crypto_assets', ['pqc_status'])
    op.create_index('ix_crypto_assets_risk_score', 'crypto_assets', ['risk_score'])


def downgrade() -> None:
    op.drop_index('ix_crypto_assets_risk_score', table_name='crypto_assets')
    op.drop_index('ix_crypto_assets_pqc_status', table_name='crypto_assets')
    op.drop_index('ix_crypto_assets_source_type', table_name='crypto_assets')
    op.drop_index('ix_crypto_assets_asset_type', table_name='crypto_assets')
    op.drop_index('ix_crypto_assets_scan_id', table_name='crypto_assets')
    op.drop_table('crypto_assets')
