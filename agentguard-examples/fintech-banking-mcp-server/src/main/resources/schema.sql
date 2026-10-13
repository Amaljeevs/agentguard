CREATE TABLE accounts (
    id VARCHAR(64) PRIMARY KEY,
    holder_name VARCHAR(128) NOT NULL,
    balance NUMERIC(15, 2) NOT NULL,
    currency VARCHAR(8) NOT NULL,
    environment VARCHAR(32) NOT NULL,
    status VARCHAR(32) NOT NULL
);

CREATE TABLE escrows (
    id VARCHAR(64) PRIMARY KEY,
    buyer_id VARCHAR(64) NOT NULL,
    seller_id VARCHAR(64) NOT NULL,
    amount NUMERIC(15, 2) NOT NULL,
    currency VARCHAR(8) NOT NULL,
    environment VARCHAR(32) NOT NULL,
    status VARCHAR(32) NOT NULL
);

CREATE TABLE corporate_batches (
    id VARCHAR(64) PRIMARY KEY,
    corporate_id VARCHAR(64) NOT NULL,
    total_amount NUMERIC(15, 2) NOT NULL,
    currency VARCHAR(8) NOT NULL,
    recipient_count INT NOT NULL,
    category VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL
);

CREATE TABLE virtual_accounts (
    virtual_iban VARCHAR(64) PRIMARY KEY,
    master_account_id VARCHAR(64) NOT NULL,
    merchant_name VARCHAR(128) NOT NULL,
    kyc_tier VARCHAR(32) NOT NULL,
    daily_limit NUMERIC(15, 2) NOT NULL,
    status VARCHAR(32) NOT NULL
);

CREATE TABLE api_clients (
    client_id VARCHAR(64) PRIMARY KEY,
    client_name VARCHAR(128) NOT NULL,
    scopes VARCHAR(256) NOT NULL,
    tier VARCHAR(64) NOT NULL,
    rate_limit_rps INT NOT NULL,
    environment VARCHAR(32) NOT NULL,
    status VARCHAR(32) NOT NULL
);
