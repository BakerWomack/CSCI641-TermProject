-- secure-db init

-- ACCOUNTS (business profile data only; no login secrets)
CREATE TABLE IF NOT EXISTS accounts (
    id SERIAL PRIMARY KEY,
    client_id TEXT UNIQUE NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    role VARCHAR(50) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- SENSITIVE DATA
CREATE TABLE IF NOT EXISTS sensitive_data (
    id SERIAL PRIMARY KEY,
    account_id INT REFERENCES accounts(id) ON DELETE SET NULL,
    data TEXT NOT NULL,
    classification VARCHAR(50) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- INDEXES
CREATE INDEX IF NOT EXISTS idx_accounts_client_id ON accounts(client_id);
CREATE INDEX IF NOT EXISTS idx_sensitive_data_account ON sensitive_data(account_id);

-- SEED DATA
-- Accounts (idempotent via unique client_id)
INSERT INTO accounts (client_id, display_name, email, role)
VALUES
('test-user-001', 'Alice Admin', 'alice@example.com', 'admin'),
('test-user-002', 'Bob Analyst', 'bob@example.com', 'analyst'),
('test-user-003', 'Carol User', 'carol@example.com', 'user')
ON CONFLICT (client_id) DO NOTHING;

-- Sensitive data (idempotent by content)
INSERT INTO sensitive_data (account_id, data, classification)
SELECT a.id, v.data, v.classification
FROM (
    VALUES
    ('test-user-001', 'Employee salaries Q1',           'high'),
    ('test-user-002', 'Customer support transcript #1', 'medium'),
    ('test-user-003', 'System maintenance note',        'low'),
    ('test-user-001', 'Incident report draft',          'high'),
    ('test-user-002', 'Internal roadmap snippet',       'medium')
) AS v(client_id, data, classification)
JOIN accounts a ON a.client_id = v.client_id
WHERE NOT EXISTS (SELECT 1 FROM sensitive_data s WHERE s.data = v.data);