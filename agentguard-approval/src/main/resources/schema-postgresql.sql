-- AgentGuard PostgreSQL schema for durable approvals
CREATE TABLE IF NOT EXISTS agentguard_approvals (
    id VARCHAR(64) PRIMARY KEY,
    subject_id VARCHAR(255) NOT NULL,
    action VARCHAR(255) NOT NULL,
    resource_type VARCHAR(255) NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    request_hash VARCHAR(128) NOT NULL,
    arguments_hash VARCHAR(128) NOT NULL,
    policy_revision VARCHAR(128) NOT NULL,
    environment VARCHAR(64) NOT NULL,
    trace_id VARCHAR(128) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    state VARCHAR(32) NOT NULL,
    decided_by VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_agentguard_approvals_subject ON agentguard_approvals (subject_id);
CREATE INDEX IF NOT EXISTS idx_agentguard_approvals_state ON agentguard_approvals (state);
CREATE INDEX IF NOT EXISTS idx_agentguard_approvals_expires ON agentguard_approvals (expires_at);
