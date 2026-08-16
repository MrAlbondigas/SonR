CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'viewer')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE hosts (
    id SERIAL PRIMARY KEY,
    ip TEXT UNIQUE NOT NULL,
    mac TEXT,
    hostname TEXT,
    os_guess TEXT,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE scans (
    id SERIAL PRIMARY KEY,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'running'
);

CREATE TABLE software (
    id SERIAL PRIMARY KEY,
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
    name TEXT NOT NULL,
    version TEXT,
    port INTEGER,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE vulnerabilities (
    id SERIAL PRIMARY KEY,
    software_id INTEGER NOT NULL REFERENCES software(id) ON DELETE CASCADE,
    cve_id TEXT,
    cvss REAL,
    severity TEXT,
    description TEXT,
    remediation TEXT,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE alerts (
    id SERIAL PRIMARY KEY,
    vulnerability_id INTEGER REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    sent_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    channel TEXT
);

CREATE INDEX idx_software_host ON software(host_id);
CREATE INDEX idx_vuln_software ON vulnerabilities(software_id);
