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
    vendor TEXT,
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
    detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    cve_checked_at TIMESTAMPTZ,
    removed_at TIMESTAMPTZ,
    UNIQUE (host_id, name, port)
);

CREATE TABLE vulnerabilities (
    id SERIAL PRIMARY KEY,
    software_id INTEGER NOT NULL REFERENCES software(id) ON DELETE CASCADE,
    cve_id TEXT,
    cvss REAL,
    severity TEXT,
    description TEXT,
    remediation TEXT,
    known_exploited BOOLEAN NOT NULL DEFAULT false,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'abierta'
);

CREATE TABLE risk_snapshots (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    host_count INTEGER NOT NULL,
    critical_count INTEGER NOT NULL,
    high_count INTEGER NOT NULL,
    medium_count INTEGER NOT NULL,
    low_count INTEGER NOT NULL,
    credential_findings INTEGER NOT NULL,
    total_score INTEGER NOT NULL
);

CREATE TABLE alerts (
    id SERIAL PRIMARY KEY,
    vulnerability_id INTEGER REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    host_id INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
    channel TEXT NOT NULL DEFAULT 'webhook',
    description TEXT,
    success BOOLEAN NOT NULL DEFAULT false,
    sent_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE events (
    id SERIAL PRIMARY KEY,
    host_id INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    description TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE credential_findings (
    id SERIAL PRIMARY KEY,
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port INTEGER NOT NULL,
    service TEXT NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    found_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (host_id, port, username)
);

CREATE TABLE demo_records (
    id SERIAL PRIMARY KEY,
    table_name TEXT NOT NULL,
    record_id INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE scan_requests (
    id SERIAL PRIMARY KEY,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    requested_by TEXT,
    consumed_at TIMESTAMPTZ
);

CREATE INDEX idx_software_host ON software(host_id);
CREATE INDEX idx_vuln_software ON vulnerabilities(software_id);
CREATE INDEX idx_events_occurred ON events(occurred_at DESC);
CREATE INDEX idx_credfindings_host ON credential_findings(host_id);
