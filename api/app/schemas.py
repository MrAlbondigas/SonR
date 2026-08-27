from pydantic import BaseModel


class SoftwareIn(BaseModel):
    name: str
    version: str | None = None
    port: int | None = None
    cpe: str | None = None
    version_source: str = "network"


class HostIn(BaseModel):
    ip: str
    mac: str | None = None
    hostname: str | None = None
    os_guess: str | None = None
    software: list[SoftwareIn] = []


class ScanIngest(BaseModel):
    hosts: list[HostIn]


class LoginIn(BaseModel):
    username: str
    password: str


class VulnerabilityIn(BaseModel):
    cve_id: str
    cvss: float | None = None
    severity: str | None = None
    description: str | None = None
    remediation: str | None = None
    known_exploited: bool = False
    match_type: str = "keyword"


class VulnerabilityIngest(BaseModel):
    software_id: int
    vulnerabilities: list[VulnerabilityIn]
    match_type: str = "keyword"


class CredentialFindingIn(BaseModel):
    host_id: int
    port: int
    service: str
    username: str
    password: str


class VulnStatusUpdate(BaseModel):
    status: str


class SSHCredentialIn(BaseModel):
    username: str
    password: str


class PracticeTargetUpdate(BaseModel):
    is_practice_target: bool


class ScanPolicyUpdate(BaseModel):
    enabled: bool
    interval_seconds: int
    excluded_ips: list[str] = []
    extra_networks: list[str] = []
    quiet_hours_start: int | None = None
    quiet_hours_end: int | None = None


class SlaPolicyUpdate(BaseModel):
    critical_days: int
    high_days: int
    medium_days: int
    low_days: int


class HostTagsUpdate(BaseModel):
    tags: list[str]


class ApiKeyCreate(BaseModel):
    name: str


class UserCreate(BaseModel):
    username: str
    password: str
    role: str


class TagAlertRouteUpdate(BaseModel):
    webhook_url: str | None = None
    email_to: str | None = None
