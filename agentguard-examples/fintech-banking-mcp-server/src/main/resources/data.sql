-- Customer Accounts
INSERT INTO accounts (id, holder_name, balance, currency, environment, status) VALUES
    ('ACC-DEV-001', 'Developer Sandbox Wallet', 10000.00, 'USD', 'development', 'ACTIVE'),
    ('ACC-DEV-002', 'Sandbox Merchant', 2500.00, 'USD', 'development', 'ACTIVE'),
    ('ACC-PROD-001', 'Enterprise Treasury Global', 1500000.00, 'USD', 'production', 'ACTIVE'),
    ('ACC-PROD-002', 'Strategic Vendor Corp', 25000.00, 'USD', 'production', 'ACTIVE'),
    ('ACC-PROD-EUR', 'Euro Liquidity Pool', 750000.00, 'EUR', 'production', 'ACTIVE'),
    ('ACC-PROD-SAR', 'Riyadh Settlement Account', 500000.00, 'SAR', 'production', 'ACTIVE'),
    ('ACC-PROD-INR', 'Mumbai Clearing Account', 45000000.00, 'INR', 'production', 'ACTIVE');

-- Escrow Contracts
INSERT INTO escrows (id, buyer_id, seller_id, amount, currency, environment, status) VALUES
    ('ESCROW-501', 'ACC-PROD-001', 'ACC-PROD-002', 12000.00, 'USD', 'production', 'ACTIVE'),
    ('ESCROW-DISPUTED-99', 'ACC-PROD-001', 'ACC-PROD-002', 45000.00, 'USD', 'production', 'DISPUTED');

-- Corporate Batch Records
INSERT INTO corporate_batches (id, corporate_id, total_amount, currency, recipient_count, category, status) VALUES
    ('BATCH-PAYROLL-101', 'CORP-ACME-INC', 85000.00, 'USD', 42, 'PAYROLL', 'PENDING'),
    ('BATCH-VENDOR-202', 'CORP-ACME-INC', 15000.00, 'USD', 3, 'VENDOR_SETTLEMENT', 'PENDING');

-- Master virtual account root
INSERT INTO accounts (id, holder_name, balance, currency, environment, status) VALUES
    ('MASTER-VA-POOL', 'Fintech Virtual Master Settlement', 2500000.00, 'USD', 'production', 'ACTIVE');

