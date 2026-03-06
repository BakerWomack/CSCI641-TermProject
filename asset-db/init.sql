-- asset-db init
CREATE TABLE IF NOT EXISTS users (
    client_id TEXT PRIMARY KEY,
    device_ids TEXT[] DEFAULT '{}',
    client_ips TEXT[] DEFAULT '{}',
    common_urls TEXT[] DEFAULT '{}',
    common_time_of_access INTEGER[] DEFAULT '{}',
    last_seen INTEGER DEFAULT 0
    username TEXT,
    password TEXT
);

