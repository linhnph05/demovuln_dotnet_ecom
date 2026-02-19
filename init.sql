CREATE DATABASE IF NOT EXISTS ecommerce;
USE ecommerce;

CREATE TABLE IF NOT EXISTS Users (
    Id INT AUTO_INCREMENT PRIMARY KEY,
    Username VARCHAR(100) NOT NULL UNIQUE,
    Email VARCHAR(200) NOT NULL,
    Password VARCHAR(200) NOT NULL,
    FullName VARCHAR(200) NOT NULL DEFAULT '',
    Role VARCHAR(50) DEFAULT 'user',
    Address TEXT,
    Phone VARCHAR(20),
    ProfileData TEXT,
    CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS Products (
    Id INT AUTO_INCREMENT PRIMARY KEY,
    Name VARCHAR(200) NOT NULL,
    Description TEXT,
    Price DECIMAL(10,2) NOT NULL,
    Stock INT DEFAULT 0,
    Category VARCHAR(100),
    ImageUrl VARCHAR(500),
    CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS Orders (
    Id INT AUTO_INCREMENT PRIMARY KEY,
    UserId INT NOT NULL,
    TotalAmount DECIMAL(10,2) NOT NULL,
    Status VARCHAR(50) DEFAULT 'Pending',
    ShippingAddress TEXT,
    Notes TEXT,
    CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS OrderItems (
    Id INT AUTO_INCREMENT PRIMARY KEY,
    OrderId INT NOT NULL,
    ProductId INT NOT NULL,
    ProductName VARCHAR(200) NOT NULL,
    Quantity INT NOT NULL,
    UnitPrice DECIMAL(10,2) NOT NULL
);

CREATE TABLE IF NOT EXISTS Reviews (
    Id INT AUTO_INCREMENT PRIMARY KEY,
    ProductId INT NOT NULL,
    UserId INT NOT NULL,
    Username VARCHAR(100) NOT NULL,
    Rating INT NOT NULL,
    Comment TEXT,
    CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Add AvatarUrl column if it doesn't exist yet (idempotent migration)
ALTER TABLE Users ADD COLUMN IF NOT EXISTS AvatarUrl VARCHAR(500) DEFAULT NULL;

-- Seed users (passwords stored in plaintext - vulnerable by design)
INSERT INTO Users (Username, Email, Password, FullName, Role) VALUES
('admin', 'admin@shopvuln.local', 'Admin@1234', 'Site Administrator', 'admin'),
('alice', 'alice@example.com', 'alice123', 'Alice Johnson', 'user'),
('bob', 'bob@example.com', 'bob123', 'Bob Smith', 'user');

-- Seed products
INSERT INTO Products (Name, Description, Price, Stock, Category, ImageUrl) VALUES
('Laptop Pro X1', 'Powerful 15-inch laptop with Intel Core i9, 32GB RAM, 1TB SSD. Perfect for developers and creatives.', 1299.99, 45, 'Electronics', 'https://images.unsplash.com/photo-1496181133206-80ce9b88a853?w=600&q=80'),
('Wireless Noise-Cancelling Headphones', 'Premium over-ear headphones with 40-hour battery life and active noise cancellation.', 249.99, 120, 'Electronics', 'https://images.unsplash.com/photo-1505740420928-5e560c06d30e?w=600&q=80'),
('Mechanical Gaming Keyboard', 'RGB backlit mechanical keyboard with Cherry MX switches. N-key rollover for gaming precision.', 89.99, 200, 'Electronics', 'https://images.unsplash.com/photo-1541140532154-b024d705b90a?w=600&q=80'),
('4K Webcam Ultra', '4K UHD webcam with autofocus, built-in ring light and stereo microphone. Plug-and-play.', 129.99, 80, 'Electronics', 'https://images.unsplash.com/photo-1587825140708-dfaf72ae4b04?w=600&q=80'),
('Ergonomic Office Chair', 'Adjustable lumbar support, breathable mesh back and 3D armrests. Ideal for long work sessions.', 449.99, 30, 'Furniture', 'https://images.unsplash.com/photo-1541558869434-2840d308329a?w=600&q=80'),
('Smart Watch Series 5', 'AMOLED display, GPS, heart-rate monitor, SpO2 sensor and 7-day battery life.', 199.99, 95, 'Wearables', 'https://images.unsplash.com/photo-1546868871-7041f2a55e12?w=600&q=80'),
('USB-C 10-in-1 Hub', 'Expand your laptop with 4K HDMI, 3x USB-A 3.0, USB-C PD, SD/MicroSD card slots and Gigabit Ethernet.', 59.99, 300, 'Accessories', 'https://images.unsplash.com/photo-1625842268584-8f3296236761?w=600&q=80'),
('Vertical Ergonomic Mouse', 'Reduces wrist strain by 57%. 2400 DPI adjustable, silent buttons, 18-month battery.', 39.99, 250, 'Electronics', 'https://images.unsplash.com/photo-1527864550417-7fd91fc51a46?w=600&q=80'),
('Laptop Backpack 17L', 'Water-resistant 17-inch laptop compartment, TSA lock, USB charging port and anti-theft pockets.', 79.99, 140, 'Bags', 'https://images.unsplash.com/photo-1553062407-98eeb64c6a62?w=600&q=80'),
('Standing Desk Converter', 'Electric height-adjustable desk converter. Supports up to 33 lbs. Dual monitor setup ready.', 329.99, 25, 'Furniture', 'https://images.unsplash.com/photo-1593642632559-0c6d3fc62b89?w=600&q=80'),
('Portable SSD 2TB', 'Ultra-fast 2TB portable SSD with USB 3.2 Gen 2. Up to 1050 MB/s read speed. Shock resistant.', 179.99, 60, 'Storage', 'https://images.unsplash.com/photo-1531492746076-161ca9bcad58?w=600&q=80'),
('LED Desk Lamp', 'Smart LED lamp with wireless charging pad, 5 color temperatures, touch dimmer and USB-A port.', 49.99, 200, 'Accessories', 'https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=600&q=80');

-- Seed reviews
INSERT INTO Reviews (ProductId, UserId, Username, Rating, Comment) VALUES
(1, 2, 'alice', 5, 'Absolutely love this laptop! Fast, reliable and the battery lasts all day.'),
(1, 3, 'bob', 4, 'Great machine. Gets a bit warm under heavy load but performance is top-notch.'),
(2, 2, 'alice', 5, 'Best headphones I have ever owned. The noise cancellation is incredible.'),
(3, 3, 'bob', 5, 'Perfect for gaming and typing. The RGB lighting looks amazing.'),
(6, 2, 'alice', 4, 'Stylish watch with great health tracking features. Battery life is impressive.');
