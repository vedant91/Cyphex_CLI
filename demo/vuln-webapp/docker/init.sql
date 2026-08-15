-- CYPHEX vuln-webapp — Database seed for DAST scanning
-- This creates intentionally vulnerable data structures for testing

CREATE DATABASE IF NOT EXISTS vulndb;
USE vulndb;

-- Users table (intentionally stores plaintext passwords for demo)
CREATE TABLE IF NOT EXISTS users (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    name       VARCHAR(100) NOT NULL,
    email      VARCHAR(255) UNIQUE NOT NULL,
    password   VARCHAR(255) NOT NULL,  -- CWE-256: plaintext password
    role       ENUM('user','admin') DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Products table
CREATE TABLE IF NOT EXISTS products (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    name        VARCHAR(200) NOT NULL,
    category    VARCHAR(100),
    price       DECIMAL(10,2),
    description TEXT
);

-- Orders table
CREATE TABLE IF NOT EXISTS orders (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    user_id    INT NOT NULL,
    product_id INT,
    status     VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Seed data
INSERT INTO users (name, email, password, role) VALUES
    ('Admin User',   'admin@example.com', 'admin123',    'admin'),
    ('Alice Johnson','alice@example.com', 'password123', 'user'),
    ('Bob Smith',    'bob@example.com',   'bob456',      'user'),
    ('Charlie Doe',  'charlie@example.com','charlie789', 'user');

INSERT INTO products (name, category, price, description) VALUES
    ('Laptop Pro',       'electronics', 999.99,  'High-performance laptop'),
    ('Wireless Mouse',   'electronics', 29.99,   'Ergonomic wireless mouse'),
    ('Mechanical Keyboard','electronics',149.99, 'RGB mechanical keyboard'),
    ('Monitor 4K',       'electronics', 399.99,  '27-inch 4K display'),
    ('USB-C Hub',        'accessories', 49.99,   '7-port USB-C hub');

INSERT INTO orders (user_id, product_id, status) VALUES
    (2, 1, 'completed'),
    (2, 2, 'pending'),
    (3, 3, 'shipped'),
    (4, 4, 'pending');

-- Grant wide permissions (intentionally insecure for demo scanning)
GRANT ALL PRIVILEGES ON vulndb.* TO 'vulnuser'@'%';
FLUSH PRIVILEGES;
