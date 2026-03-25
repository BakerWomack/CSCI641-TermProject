-- secure-db init

-- USERS
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role VARCHAR(50) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- DEVICES
CREATE TABLE IF NOT EXISTS devices (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id VARCHAR(100) UNIQUE NOT NULL,
    device_name VARCHAR(50) NOT NULL,
    device_type VARCHAR(50) NOT NULL,
    is_trusted BOOLEAN NOT NULL DEFAULT FALSE,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    common_urls TEXT[] DEFAULT '{}',
    common_time_of_access INTEGER[] DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- TRUST SCORES
CREATE TABLE IF NOT EXISTS trust_scores (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id INT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    trust_score FLOAT NOT NULL,
    evaluation_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ACCESS LOGS
CREATE TABLE IF NOT EXISTS access_logs (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    device_id INT REFERENCES devices(id) ON DELETE CASCADE,
    endpoint VARCHAR(100),
    status VARCHAR(20),
    reason TEXT,
    access_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- SENSITIVE DATA
CREATE TABLE IF NOT EXISTS sensitive_data (
    id SERIAL PRIMARY KEY,
    data TEXT NOT NULL,
    classification VARCHAR(50) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- INDEXES
CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id);
CREATE INDEX IF NOT EXISTS idx_trust_user_device ON trust_scores(user_id, device_id);
CREATE INDEX IF NOT EXISTS idx_access_logs_user ON access_logs(user_id);

-- SEED DATA
-- Users (idempotent via unique username)
INSERT INTO users (username, password_hash, role)
VALUES
('alice', 'dev_hash_alice', 'admin'),
('bob',   'dev_hash_bob',   'analyst'),
('carol', 'dev_hash_carol', 'user')
ON CONFLICT (username) DO NOTHING;

-- Devices (idempotent via unique device_id)
INSERT INTO devices (user_id, device_id, device_name, device_type, is_trusted, common_urls, common_time_of_access)
SELECT u.id, v.device_id, v.device_name, v.device_type, v.is_trusted, v.common_urls, v.common_time_of_access
FROM (
    VALUES
    ('alice', 'dev-alice-laptop-001', 'Alice Laptop', 'laptop', TRUE,  ARRAY['/app/data','/app/profile'], ARRAY[9,10,11,14,15]),
    ('alice', 'dev-alice-phone-001',  'Alice Phone',  'phone',  FALSE, ARRAY['/app/data'],               ARRAY[18,19,20]),
    ('bob',   'dev-bob-ws-001',       'Bob WS',       'desktop',TRUE,  ARRAY['/app/data'],               ARRAY[8,9,10,16]),
    ('carol', 'dev-carol-tablet-001', 'Carol Tablet', 'tablet', FALSE, ARRAY['/app/data'],               ARRAY[12,13])
) AS v(username, device_id, device_name, device_type, is_trusted, common_urls, common_time_of_access)
JOIN users u ON u.username = v.username
WHERE NOT EXISTS (SELECT 1 FROM devices d WHERE d.device_id = v.device_id);

-- Trust scores (keep a few recent samples; avoid duplicates with a WHERE NOT EXISTS guard)
INSERT INTO trust_scores (user_id, device_id, trust_score)
SELECT u.id, d.id, v.trust_score
FROM (
    VALUES
    ('alice', 'dev-alice-laptop-001', 0.95),
    ('alice', 'dev-alice-phone-001',  0.45),
    ('bob',   'dev-bob-ws-001',       0.85),
    ('carol', 'dev-carol-tablet-001', 0.55)
) AS v(username, device_id, trust_score)
JOIN users u   ON u.username = v.username
JOIN devices d ON d.device_id = v.device_id AND d.user_id = u.id
WHERE NOT EXISTS (
    SELECT 1
    FROM trust_scores ts
    WHERE ts.user_id = u.id AND ts.device_id = d.id AND ts.trust_score = v.trust_score
);

-- Access logs (sample mix of allowed/denied)
INSERT INTO access_logs (user_id, device_id, endpoint, status, reason)
SELECT u.id, d.id, v.endpoint, v.status, v.reason
FROM (
    VALUES
    ('alice', 'dev-alice-laptop-001', '/app/data', 'allowed', 'trusted device'),
    ('alice', 'dev-alice-phone-001',  '/app/data', 'denied',  'low trust score'),
    ('bob',   'dev-bob-ws-001',       '/app/data', 'allowed', 'baseline access'),
    ('carol', 'dev-carol-tablet-001', '/app/data', 'denied',  'untrusted device')
) AS v(username, device_id, endpoint, status, reason)
JOIN users u   ON u.username = v.username
JOIN devices d ON d.device_id = v.device_id AND d.user_id = u.id
WHERE NOT EXISTS (
    SELECT 1
    FROM access_logs al
    WHERE al.user_id = u.id
      AND al.device_id = d.id
      AND al.endpoint = v.endpoint
      AND al.status = v.status
      AND COALESCE(al.reason, '') = COALESCE(v.reason, '')
);

-- Sensitive data (idempotent by content)
INSERT INTO sensitive_data (data, classification)
SELECT v.data, v.classification
FROM (
    VALUES
    ('Employee salaries Q1',           'high'),
    ('Customer support transcript #1', 'medium'),
    ('System maintenance note',        'low'),
    ('Incident report draft',          'high'),
    ('Internal roadmap snippet',       'medium')
) AS v(data, classification)
WHERE NOT EXISTS (SELECT 1 FROM sensitive_data s WHERE s.data = v.data);