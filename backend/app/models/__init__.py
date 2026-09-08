"""Database models package.

All models MUST be imported here so that Base.metadata.create_all()
discovers them when creating database tables on startup.
"""

from app.models.scan import ScanJob
from app.models.asset import Asset
from app.models.cbom import CBOMRecord
from app.models.certificate import PQCCertificate
from app.models.crypto_asset import CryptoAsset

__all__ = ["ScanJob", "Asset", "CBOMRecord", "PQCCertificate", "CryptoAsset"]
