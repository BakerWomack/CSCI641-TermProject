-- asset-db init
CREATE TABLE IF NOT EXISTS users (
    client_id TEXT PRIMARY KEY,
    device_ids TEXT[] DEFAULT '{}',
    client_ips TEXT[] DEFAULT '{}',
    common_urls TEXT[] DEFAULT '{}',
    common_time_of_access INTEGER[] DEFAULT '{}',
    last_seen INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS auth_clients (
    client_id TEXT PRIMARY KEY,
    client_secret TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO auth_clients (client_id, client_secret, active)
VALUES
('test-user-001', 'secret001', TRUE)
ON CONFLICT (client_id) DO UPDATE
SET client_secret = EXCLUDED.client_secret,
    active = EXCLUDED.active;

INSERT INTO users (client_id, device_ids, client_ips, common_urls, common_time_of_access, last_seen)
VALUES
(
    'test-user-001',
    ARRAY['dev-alice-laptop-001'],
    ARRAY['127.0.0.1','::1'],
    ARRAY['https://localhost/api/login','https://localhost/api/app/data','https://localhost/_authz','/api/login','/api/app/data','/_authz'],
    ARRAY[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23],
    0
)
ON CONFLICT (client_id) DO UPDATE
SET device_ids = EXCLUDED.device_ids,
    common_urls = EXCLUDED.common_urls,
    common_time_of_access = EXCLUDED.common_time_of_access;

