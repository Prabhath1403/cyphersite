"""Initial migration - create all tables

Revision ID: 001
Revises: None
Create Date: 2025-01-01
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = '001'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Scan Jobs
    op.create_table(
        'scan_jobs',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('target', sa.String(500), nullable=False, index=True),
        sa.Column('status', sa.String(20), nullable=False, default='queued', index=True),
        sa.Column('scan_depth', sa.String(10), nullable=False, default='quick'),
        sa.Column('created_at', sa.DateTime, nullable=False),
        sa.Column('completed_at', sa.DateTime, nullable=True),
        sa.Column('total_assets', sa.Integer, default=0),
        sa.Column('quantum_safe_count', sa.Integer, default=0),
        sa.Column('vulnerable_count', sa.Integer, default=0),
        sa.Column('hybrid_count', sa.Integer, default=0),
        sa.Column('error_message', sa.Text, nullable=True),
    )

    # Assets
    op.create_table(
        'assets',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('scan_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('scan_jobs.id'), nullable=False, index=True),
        sa.Column('hostname', sa.String(500), nullable=False, index=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('port', sa.Integer, nullable=False, default=443),
        sa.Column('service_type', sa.String(20), nullable=False, default='web_server'),
        sa.Column('tls_versions', postgresql.JSONB, nullable=True),
        sa.Column('cipher_suites', postgresql.JSONB, nullable=True),
        sa.Column('certificate', postgresql.JSONB, nullable=True),
        sa.Column('key_exchange', sa.String(100), nullable=True),
        sa.Column('cert_chain_length', sa.Integer, nullable=True),
        sa.Column('hsts_enabled', sa.String(10), nullable=True),
        sa.Column('ocsp_stapling', sa.String(10), nullable=True),
        sa.Column('pqc_status', sa.String(20), nullable=True),
        sa.Column('risk_score', sa.Float, nullable=True),
        sa.Column('vulnerabilities', postgresql.JSONB, nullable=True),
        sa.Column('recommendations', postgresql.JSONB, nullable=True),
        sa.Column('created_at', sa.DateTime, nullable=False),
    )

    # CBOM Records
    op.create_table(
        'cbom_records',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('scan_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('scan_jobs.id'), nullable=False, index=True, unique=True),
        sa.Column('cyclonedx_json', sa.Text, nullable=False),
        sa.Column('created_at', sa.DateTime, nullable=False),
    )

    # PQC Certificates
    op.create_table(
        'pqc_certificates',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('asset_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('assets.id'), nullable=False, unique=True),
        sa.Column('cert_id', postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column('status', sa.String(30), nullable=False),
        sa.Column('algorithms_verified', postgresql.JSONB, nullable=False),
        sa.Column('fingerprint', sa.String(128), nullable=False),
        sa.Column('issued_at', sa.DateTime, nullable=False),
        sa.Column('valid_until', sa.DateTime, nullable=False),
        sa.Column('badge_svg_path', sa.String(500), nullable=True),
        sa.Column('badge_png_path', sa.String(500), nullable=True),
        sa.Column('qr_path', sa.String(500), nullable=True),
    )


def downgrade() -> None:
    op.drop_table('pqc_certificates')
    op.drop_table('cbom_records')
    op.drop_table('assets')
    op.drop_table('scan_jobs')
