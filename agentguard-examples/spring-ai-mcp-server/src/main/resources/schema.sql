CREATE TABLE orders (id BIGINT PRIMARY KEY, environment VARCHAR(30) NOT NULL, product VARCHAR(100) NOT NULL, status VARCHAR(20) NOT NULL);
INSERT INTO orders VALUES (1, 'development', 'Dev subscription', 'PAID'), (2, 'production', 'Prod subscription', 'PAID');
