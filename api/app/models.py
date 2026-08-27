from sqlalchemy import REAL, Boolean, Column, ForeignKey, Integer, Text, TIMESTAMP
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from .crypto import EncryptedString
from .database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(Text, unique=True, nullable=False)
    password_hash = Column(Text, nullable=False)
    role = Column(Text, nullable=False)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())


class LoginAttempt(Base):
    __tablename__ = "login_attempts"

    id = Column(Integer, primary_key=True)
    username = Column(Text, nullable=False)
    ip_address = Column(Text)
    success = Column(Boolean, nullable=False)
    attempted_at = Column(TIMESTAMP(timezone=True), server_default=func.now())


class Host(Base):
    __tablename__ = "hosts"

    id = Column(Integer, primary_key=True)
    ip = Column(Text, unique=True, nullable=False)
    mac = Column(Text)
    vendor = Column(Text)
    hostname = Column(Text)
    os_guess = Column(Text)
    is_practice_target = Column(Boolean, nullable=False, default=False)
    first_seen = Column(TIMESTAMP(timezone=True), server_default=func.now())
    last_seen = Column(TIMESTAMP(timezone=True), server_default=func.now())

    software = relationship("Software", back_populates="host", cascade="all, delete-orphan")
    credential_findings = relationship(
        "CredentialFinding", back_populates="host", cascade="all, delete-orphan"
    )
    tags = relationship("HostTag", back_populates="host", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True)
    started_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    finished_at = Column(TIMESTAMP(timezone=True))
    status = Column(Text, nullable=False, default="running")


class DemoRecord(Base):
    __tablename__ = "demo_records"

    id = Column(Integer, primary_key=True)
    table_name = Column(Text, nullable=False)
    record_id = Column(Integer, nullable=False)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())


class ScanRequest(Base):
    __tablename__ = "scan_requests"

    id = Column(Integer, primary_key=True)
    requested_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    requested_by = Column(Text)
    consumed_at = Column(TIMESTAMP(timezone=True))


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id", ondelete="CASCADE"))
    host_id = Column(Integer, ForeignKey("hosts.id", ondelete="CASCADE"))
    channel = Column(Text, nullable=False, default="webhook")
    description = Column(Text)
    success = Column(Boolean, nullable=False, default=False)
    sent_at = Column(TIMESTAMP(timezone=True), server_default=func.now())


class RiskSnapshot(Base):
    __tablename__ = "risk_snapshots"

    id = Column(Integer, primary_key=True)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    host_count = Column(Integer, nullable=False)
    critical_count = Column(Integer, nullable=False)
    high_count = Column(Integer, nullable=False)
    medium_count = Column(Integer, nullable=False)
    low_count = Column(Integer, nullable=False)
    credential_findings = Column(Integer, nullable=False)
    total_score = Column(Integer, nullable=False)


class SSHCredential(Base):
    __tablename__ = "ssh_credentials"

    host_id = Column(Integer, ForeignKey("hosts.id", ondelete="CASCADE"), primary_key=True)
    username = Column(Text, nullable=False)
    password = Column(EncryptedString, nullable=False)
    updated_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    updated_by = Column(Text)


class PatchLog(Base):
    __tablename__ = "patch_log"

    id = Column(Integer, primary_key=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id", ondelete="SET NULL"))
    host_id = Column(Integer, ForeignKey("hosts.id", ondelete="CASCADE"))
    command = Column(Text, nullable=False)
    success = Column(Boolean, nullable=False)
    output = Column(Text)
    executed_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    executed_by = Column(Text)

    host = relationship("Host")


class PocAttempt(Base):
    __tablename__ = "poc_attempts"

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey("hosts.id", ondelete="CASCADE"))
    credential_finding_id = Column(Integer, ForeignKey("credential_findings.id", ondelete="SET NULL"))
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id", ondelete="SET NULL"))
    poc_type = Column(Text, nullable=False)
    success = Column(Boolean, nullable=False)
    detail = Column(Text)
    executed_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    executed_by = Column(Text)

    host = relationship("Host")


class ScanPolicy(Base):
    __tablename__ = "scan_policy"

    id = Column(Integer, primary_key=True)
    enabled = Column(Boolean, nullable=False, default=True)
    interval_seconds = Column(Integer, nullable=False, default=300)
    excluded_ips = Column(Text, nullable=False, default="")
    quiet_hours_start = Column(Integer)
    quiet_hours_end = Column(Integer)
    updated_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    updated_by = Column(Text)


class SlaPolicy(Base):
    __tablename__ = "sla_policy"

    id = Column(Integer, primary_key=True)
    critical_days = Column(Integer, nullable=False, default=7)
    high_days = Column(Integer, nullable=False, default=30)
    medium_days = Column(Integer, nullable=False, default=90)
    low_days = Column(Integer, nullable=False, default=180)
    updated_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    updated_by = Column(Text)


class HostTag(Base):
    __tablename__ = "host_tags"

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False)
    tag = Column(Text, nullable=False)

    host = relationship("Host", back_populates="tags")


class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True)
    name = Column(Text, nullable=False)
    key_prefix = Column(Text, nullable=False)
    key_hash = Column(Text, nullable=False, unique=True)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    created_by = Column(Text)
    last_used_at = Column(TIMESTAMP(timezone=True))
    revoked_at = Column(TIMESTAMP(timezone=True))


class Software(Base):
    __tablename__ = "software"

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="SET NULL"))
    name = Column(Text, nullable=False)
    version = Column(Text)
    port = Column(Integer)
    cpe = Column(Text)
    version_source = Column(Text, nullable=False, default="network")
    detected_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    cve_checked_at = Column(TIMESTAMP(timezone=True))
    last_check_method = Column(Text)
    removed_at = Column(TIMESTAMP(timezone=True))
    missed_scans = Column(Integer, nullable=False, default=0)

    host = relationship("Host", back_populates="software")
    vulnerabilities = relationship(
        "Vulnerability", back_populates="software", cascade="all, delete-orphan"
    )


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True)
    software_id = Column(Integer, ForeignKey("software.id", ondelete="CASCADE"), nullable=False)
    cve_id = Column(Text)
    cvss = Column(REAL)
    severity = Column(Text)
    description = Column(Text)
    remediation = Column(Text)
    known_exploited = Column(Boolean, nullable=False, default=False)
    detected_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    resolved_at = Column(TIMESTAMP(timezone=True))
    status = Column(Text, nullable=False, default="abierta")
    match_type = Column(Text, nullable=False, default="keyword")
    sla_due_at = Column(TIMESTAMP(timezone=True))

    software = relationship("Software", back_populates="vulnerabilities")


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey("hosts.id", ondelete="CASCADE"))
    event_type = Column(Text, nullable=False)
    description = Column(Text, nullable=False)
    occurred_at = Column(TIMESTAMP(timezone=True), server_default=func.now())


class CredentialFinding(Base):
    __tablename__ = "credential_findings"

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False)
    port = Column(Integer, nullable=False)
    service = Column(Text, nullable=False)
    username = Column(Text, nullable=False)
    password = Column(EncryptedString, nullable=False)
    found_at = Column(TIMESTAMP(timezone=True), server_default=func.now())

    host = relationship("Host", back_populates="credential_findings")
