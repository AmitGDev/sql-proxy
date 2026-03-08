CREATE TABLE customers (
    id    SERIAL PRIMARY KEY,
    name  TEXT NOT NULL,
    email TEXT NOT NULL,
    phone TEXT
);

CREATE TABLE products (
    id    SERIAL PRIMARY KEY,
    name  TEXT NOT NULL,
    price NUMERIC(10,2)
);

CREATE TABLE orders (
    id          SERIAL PRIMARY KEY,
    customer_id INTEGER REFERENCES customers(id),
    created_at  TIMESTAMP DEFAULT NOW()
);

CREATE TABLE order_items (
    id         SERIAL PRIMARY KEY,
    order_id   INTEGER REFERENCES orders(id),
    product_id INTEGER REFERENCES products(id),
    quantity   INTEGER,
    unit_price NUMERIC(10,2)
);

INSERT INTO customers (name, email, phone) VALUES
    ('Alice Smith',  'alice@example.com',  '555-0101'),
    ('Bob Jones',    'bob@example.com',    '555-0102'),
    ('Carol White',  'carol@example.com',  NULL),
    ('David Brown',  'david@example.com',  '555-0104');

INSERT INTO products (name, price) VALUES
    ('Laptop',    999.99),
    ('Mouse',      29.99),
    ('Keyboard',   79.99),
    ('Monitor',   399.99),
    ('Headphones', 149.99);

INSERT INTO orders (customer_id) VALUES (1),(1),(2),(3),(4);

INSERT INTO order_items (order_id, product_id, quantity, unit_price) VALUES
    (1,1,1,999.99),(1,2,2,29.99),(2,5,1,149.99),
    (3,3,1,79.99),(3,4,2,399.99),(4,2,3,29.99),
    (5,1,1,999.99),(5,3,1,79.99);