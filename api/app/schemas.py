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
