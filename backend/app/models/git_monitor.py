import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, DateTime, Text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from app.database import Base

class GitMonitorEvent(Base):
    """Audit log of git commit and file change events processed in real-time."""
    __tablename__ = "git_monitor_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    repository = Column(String(500), nullable=False, index=True)
    branch = Column(String(100), default="main")
    commit_id = Column(String(100), nullable=False)
    commit_message = Column(String(500), nullable=False)
    author = Column(String(200), default="Developer")
    file_path = Column(String(500), nullable=False)
    action = Column(String(50), default="modified")  # modified, added, removed, remediated
    vulnerabilities_fixed = Column(Integer, default=0)
    vulnerabilities_remaining = Column(Integer, default=0)
    quantum_safe_count = Column(Integer, default=0)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scan_jobs.id"), nullable=True)
    duration_ms = Column(Float, default=0.0)
    diff_summary = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    def to_dict(self):
        return {
            "id": str(self.id),
            "repository": self.repository,
            "branch": self.branch,
            "commit_id": self.commit_id,
            "commit_message": self.commit_message,
            "author": self.author,
            "file_path": self.file_path,
            "action": self.action,
            "vulnerabilities_fixed": self.vulnerabilities_fixed,
            "vulnerabilities_remaining": self.vulnerabilities_remaining,
            "quantum_safe_count": self.quantum_safe_count,
            "scan_id": str(self.scan_id) if self.scan_id else None,
            "duration_ms": self.duration_ms,
            "diff_summary": self.diff_summary,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
