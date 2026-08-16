from pydantic import BaseModel


class SoftwareIn(BaseModel):
    name: str
    version: str | None = None
    port: int | None = None


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


class VulnerabilityIngest(BaseModel):
    software_id: int
    vulnerabilities: list[VulnerabilityIn]
