CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'viewer')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE login_attempts (
    id SERIAL PRIMARY KEY,
    username TEXT NOT NULL,
    ip_address TEXT,
    success BOOLEAN NOT NULL,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE hosts (
    id SERIAL PRIMARY KEY,
    ip TEXT UNIQUE NOT NULL,
    mac TEXT,
    vendor TEXT,
    hostname TEXT,
    os_guess TEXT,
    is_practice_target BOOLEAN NOT NULL DEFAULT false,
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
    cpe TEXT,
    version_source TEXT NOT NULL DEFAULT 'network',
    detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    cve_checked_at TIMESTAMPTZ,
    last_check_method TEXT,
    removed_at TIMESTAMPTZ,
    missed_scans INTEGER NOT NULL DEFAULT 0,
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
    status TEXT NOT NULL DEFAULT 'abierta',
    match_type TEXT NOT NULL DEFAULT 'keyword',
    sla_due_at TIMESTAMPTZ
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

CREATE TABLE ssh_credentials (
    host_id INTEGER PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by TEXT
);

CREATE TABLE patch_log (
    id SERIAL PRIMARY KEY,
    vulnerability_id INTEGER REFERENCES vulnerabilities(id) ON DELETE SET NULL,
    host_id INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
    command TEXT NOT NULL,
    success BOOLEAN NOT NULL,
    output TEXT,
    executed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    executed_by TEXT
);

CREATE TABLE poc_attempts (
    id SERIAL PRIMARY KEY,
    host_id INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
    credential_finding_id INTEGER REFERENCES credential_findings(id) ON DELETE SET NULL,
    vulnerability_id INTEGER REFERENCES vulnerabilities(id) ON DELETE SET NULL,
    poc_type TEXT NOT NULL,
    success BOOLEAN NOT NULL,
    detail TEXT,
    executed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    executed_by TEXT
);

CREATE TABLE scan_policy (
    id SERIAL PRIMARY KEY,
    enabled BOOLEAN NOT NULL DEFAULT true,
    interval_seconds INTEGER NOT NULL DEFAULT 300,
    excluded_ips TEXT NOT NULL DEFAULT '',
    quiet_hours_start INTEGER,
    quiet_hours_end INTEGER,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by TEXT
);

CREATE TABLE sla_policy (
    id SERIAL PRIMARY KEY,
    critical_days INTEGER NOT NULL DEFAULT 7,
    high_days INTEGER NOT NULL DEFAULT 30,
    medium_days INTEGER NOT NULL DEFAULT 90,
    low_days INTEGER NOT NULL DEFAULT 180,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by TEXT
);

CREATE TABLE host_tags (
    id SERIAL PRIMARY KEY,
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    tag TEXT NOT NULL,
    UNIQUE (host_id, tag)
);

CREATE TABLE api_keys (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by TEXT,
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX idx_software_host ON software(host_id);
CREATE INDEX idx_host_tags_host ON host_tags(host_id);
CREATE INDEX idx_host_tags_tag ON host_tags(tag);
CREATE INDEX idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX idx_vuln_sla_due ON vulnerabilities(sla_due_at) WHERE resolved_at IS NULL;
CREATE INDEX idx_vuln_software ON vulnerabilities(software_id);
CREATE INDEX idx_events_occurred ON events(occurred_at DESC);
CREATE INDEX idx_credfindings_host ON credential_findings(host_id);
CREATE INDEX idx_login_attempts_username ON login_attempts(username, attempted_at);
CREATE INDEX idx_login_attempts_ip ON login_attempts(ip_address, attempted_at);
