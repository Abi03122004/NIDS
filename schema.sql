-- schema.sql
-- SQLite schema for persisting IDS predictions, incidents, and users

DROP TABLE IF EXISTS predictions;
DROP TABLE IF EXISTS incidents;

CREATE TABLE predictions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    prediction TEXT NOT NULL,
    confidence REAL NOT NULL,
    severity TEXT NOT NULL,
    latency_ms REAL NOT NULL,
    imputed_count INTEGER NOT NULL,
    src_ip TEXT NOT NULL DEFAULT '127.0.0.1',
    dst_ip TEXT NOT NULL DEFAULT '127.0.0.1',
    src_port INTEGER NOT NULL DEFAULT 0,
    dst_port INTEGER NOT NULL DEFAULT 0,
    protocol INTEGER NOT NULL DEFAULT 0, -- 6 = TCP, 17 = UDP, etc.
    detection_method TEXT NOT NULL DEFAULT 'BEHAVIOR', -- 'SIGNATURE' or 'BEHAVIOR'
    details TEXT NOT NULL DEFAULT ''
);

-- Incidents table for aggregated notifications
CREATE TABLE incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    start_time TEXT NOT NULL,
    last_update TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    attack_type TEXT NOT NULL,
    event_count INTEGER NOT NULL DEFAULT 1,
    severity TEXT NOT NULL,
    status TEXT NOT NULL, -- 'ACTIVE', 'RESOLVED'
    notified INTEGER NOT NULL DEFAULT 0 -- 0 = Not notified, 1 = Notified
);

-- Users table for authentication
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- Indexes for performance tuning
CREATE INDEX IF NOT EXISTS idx_predictions_timestamp ON predictions(timestamp);
CREATE INDEX IF NOT EXISTS idx_predictions_prediction ON predictions(prediction);
CREATE INDEX IF NOT EXISTS idx_predictions_severity ON predictions(severity);
CREATE INDEX IF NOT EXISTS idx_predictions_src_ip ON predictions(src_ip);
CREATE INDEX IF NOT EXISTS idx_incidents_status_ip ON incidents(status, src_ip);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
