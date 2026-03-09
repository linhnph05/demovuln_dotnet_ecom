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
    CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    AvatarUrl VARCHAR(500) DEFAULT NULL
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

INSERT INTO Users (Username, Email, Password, FullName, Role) VALUES
('admin', 'admin@shopvuln.local', 'Admin@1234', 'Site Administrator', 'admin'),
('alice', 'alice@example.com', 'alice123', 'Alice Johnson', 'user'),
('bob', 'bob@example.com', 'bob123', 'Bob Smith', 'user'),
('charlie', 'charlie@example.com', 'charlie456', 'Charlie Davis', 'user'),
('diana', 'diana@example.com', 'diana789', 'Diana Martinez', 'user'),
('edward', 'edward@example.com', 'edward321', 'Edward Wilson', 'user'),
('fiona', 'fiona@example.com', 'fiona654', 'Fiona Taylor', 'user'),
('george', 'george@example.com', 'george987', 'George Anderson', 'user'),
('hannah', 'hannah@example.com', 'hannah234', 'Hannah Thomas', 'user'),
('isaac', 'isaac@example.com', 'isaac567', 'Isaac Jackson', 'user'),
('julia', 'julia@example.com', 'julia890', 'Julia White', 'user');

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
('LED Desk Lamp', 'Smart LED lamp with wireless charging pad, 5 color temperatures, touch dimmer and USB-A port.', 49.99, 200, 'Accessories', 'https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=600&q=80'),
('Bluetooth Speaker Pro', 'Waterproof portable speaker with 360° sound, 24-hour battery and TWS pairing capability.', 99.99, 150, 'Electronics', 'https://images.unsplash.com/photo-1608043152269-423dbba4e7e1?w=600&q=80'),
('Wireless Charger Pad', 'Fast 15W wireless charging pad with cooling fan. Compatible with all Qi-enabled devices.', 29.99, 350, 'Accessories', 'https://images.unsplash.com/photo-1591290619762-c588d04d1e61?w=600&q=80'),
('Gaming Monitor 27"', '27-inch QHD 165Hz gaming monitor with 1ms response time, HDR400 and FreeSync Premium.', 399.99, 55, 'Electronics', 'https://images.unsplash.com/photo-1527443224154-c4a3942d3acf?w=600&q=80'),
('Webcam Privacy Cover', 'Ultra-thin magnetic camera cover for laptops, tablets and phones. Pack of 6.', 9.99, 500, 'Accessories', 'https://images.unsplash.com/photo-1588508065123-287b28e013da?w=600&q=80'),
('Laptop Cooling Pad', '5-fan cooling pad with adjustable height and LED lights. Fits laptops up to 17 inches.', 34.99, 180, 'Accessories', 'https://images.unsplash.com/photo-1625842268584-8f3296236761?w=600&q=80'),
('Microphone USB Condenser', 'Professional USB condenser microphone with pop filter, shock mount and tripod stand.', 79.99, 90, 'Electronics', 'https://images.unsplash.com/photo-1590602847861-f357a9332bbc?w=600&q=80'),
('Cable Management Kit', 'Complete cable organizer set with clips, sleeves, ties and labels. Tidy desk solution.', 19.99, 400, 'Accessories', 'https://images.unsplash.com/photo-1558618666-fcd25c85cd64?w=600&q=80'),
('Mechanical Numpad', 'Wireless mechanical numpad with Cherry MX switches. Perfect for data entry and accounting.', 44.99, 120, 'Electronics', 'https://images.unsplash.com/photo-1587829741301-dc798b83add3?w=600&q=80'),
('Phone Stand Adjustable', 'Aluminum adjustable phone/tablet stand with anti-slip silicone pads. Fits 4-13 inch devices.', 24.99, 280, 'Accessories', 'https://images.unsplash.com/photo-1598327105666-5b89351aff97?w=600&q=80'),
('External Hard Drive 4TB', 'USB 3.1 external hard drive with hardware encryption and automatic backup software.', 119.99, 75, 'Storage', 'https://images.unsplash.com/photo-1531492746076-161ca9bcad58?w=600&q=80'),
('Desk Mat XXL', 'Extended 35" x 15" desk mat with stitched edges, waterproof surface and non-slip rubber base.', 29.99, 220, 'Accessories', 'https://images.unsplash.com/photo-1625842268584-8f3296236761?w=600&q=80'),
('Monitor Light Bar', 'E-reading LED lamp that clips onto monitor. Auto-dimming, no glare, USB powered.', 89.99, 65, 'Accessories', 'https://images.unsplash.com/photo-1558618666-fcd25c85cd64?w=600&q=80'),
('Fitness Tracker Band', 'Water-resistant fitness tracker with heart rate, sleep monitor, step counter and 10-day battery.', 49.99, 200, 'Wearables', 'https://images.unsplash.com/photo-1575311373937-040b8e1fd5b6?w=600&q=80');

INSERT INTO Reviews (ProductId, UserId, Username, Rating, Comment) VALUES
(1, 2, 'alice', 5, 'Absolutely love this laptop! Fast, reliable and the battery lasts all day.'),
(1, 3, 'bob', 4, 'Great machine. Gets a bit warm under heavy load but performance is top-notch.'),
(2, 2, 'alice', 5, 'Best headphones I have ever owned. The noise cancellation is incredible.'),
(3, 3, 'bob', 5, 'Perfect for gaming and typing. The RGB lighting looks amazing.'),
(6, 2, 'alice', 4, 'Stylish watch with great health tracking features. Battery life is impressive.'),
(1, 4, 'charlie', 5, 'Worth every penny. The build quality is exceptional.'),
(2, 5, 'diana', 5, 'Amazing sound quality and very comfortable for long use.'),
(3, 6, 'edward', 4, 'Solid keyboard. The mechanical switches feel great.'),
(4, 7, 'fiona', 5, 'Crystal clear video quality. Perfect for video calls.'),
(5, 8, 'george', 5, 'Most comfortable chair I have ever used. Back pain is gone!'),
(6, 9, 'hannah', 5, 'Love all the fitness tracking features. Very accurate.'),
(7, 10, 'isaac', 4, 'Great hub with all the ports I need. Works flawlessly.'),
(8, 11, 'julia', 5, 'My wrist pain has decreased significantly. Highly recommend.'),
(9, 4, 'charlie', 4, 'Spacious and well-organized. Fits my 15-inch laptop perfectly.'),
(10, 5, 'diana', 5, 'Game changer for my standing desk setup. Smooth transitions.'),
(11, 6, 'edward', 5, 'Super fast transfer speeds. Very portable and sturdy.'),
(12, 7, 'fiona', 5, 'Love the wireless charging feature. Very convenient.'),
(13, 8, 'george', 5, 'Amazing bass and volume. Great for outdoor use.'),
(14, 9, 'hannah', 4, 'Charges my phone quickly. Gets a bit warm during fast charging.'),
(15, 10, 'isaac', 5, 'Stunning display and smooth gaming experience. No more screen tearing.'),
(16, 11, 'julia', 5, 'Simple but effective. Peace of mind for privacy.'),
(17, 2, 'alice', 4, 'Keeps my laptop cool during intensive tasks. A bit noisy on max speed.'),
(18, 3, 'bob', 5, 'Professional sound quality. Great for podcasting and streaming.'),
(19, 4, 'charlie', 5, 'Finally organized all my cables. Desk looks so much cleaner.'),
(20, 5, 'diana', 4, 'Solid build quality. Works great for Excel work.'),
(2, 6, 'edward', 5, 'Noise cancellation is unmatched. Battery lasts forever.'),
(3, 7, 'fiona', 5, 'Best keyboard for the price. The RGB is customizable too.'),
(6, 8, 'george', 4, 'Great fitness tracking. Wish the screen was a bit larger.'),
(11, 9, 'hannah', 4, 'Fast and reliable storage. Good value for the capacity.'),
(15, 4, 'charlie', 5, 'Colors are vibrant and the refresh rate is incredible.');

INSERT INTO Orders (UserId, TotalAmount, Status, ShippingAddress, Notes) VALUES
(2, 1549.98, 'Delivered', '123 Oak Street, Springfield, IL 62701', 'Please leave at front door'),
(3, 179.98, 'Shipped', '456 Elm Avenue, Portland, OR 97201', 'Call on arrival'),
(4, 1729.97, 'Delivered', '789 Pine Road, Austin, TX 78701', NULL),
(5, 329.99, 'Processing', '321 Maple Drive, Seattle, WA 98101', 'Gift wrap please'),
(6, 449.97, 'Delivered', '654 Cedar Lane, Denver, CO 80201', NULL),
(7, 159.98, 'Shipped', '987 Birch Court, Boston, MA 02101', 'Leave with concierge'),
(8, 539.97, 'Delivered', '147 Walnut Street, Miami, FL 33101', NULL),
(9, 199.99, 'Processing', '258 Cherry Boulevard, Chicago, IL 60601', 'Fragile - handle with care'),
(10, 889.96, 'Delivered', '369 Ash Avenue, Phoenix, AZ 85001', NULL),
(11, 264.97, 'Shipped', '741 Spruce Way, Atlanta, GA 30301', 'Deliver after 6 PM'),
(2, 679.97, 'Delivered', '123 Oak Street, Springfield, IL 62701', NULL),
(3, 1329.98, 'Processing', '456 Elm Avenue, Portland, OR 97201', 'Business address'),
(4, 99.99, 'Delivered', '789 Pine Road, Austin, TX 78701', NULL),
(5, 849.96, 'Shipped', '321 Maple Drive, Seattle, WA 98101', NULL),
(6, 119.99, 'Delivered', '654 Cedar Lane, Denver, CO 80201', 'Leave in mailroom');

INSERT INTO OrderItems (OrderId, ProductId, ProductName, Quantity, UnitPrice) VALUES
(1, 1, 'Laptop Pro X1', 1, 1299.99),
(1, 2, 'Wireless Noise-Cancelling Headphones', 1, 249.99),
(2, 8, 'Vertical Ergonomic Mouse', 2, 39.99),
(2, 13, 'Bluetooth Speaker Pro', 1, 99.99),
(3, 1, 'Laptop Pro X1', 1, 1299.99),
(3, 5, 'Ergonomic Office Chair', 1, 449.99),
(4, 10, 'Standing Desk Converter', 1, 329.99),
(5, 5, 'Ergonomic Office Chair', 1, 449.99),
(6, 7, 'USB-C 10-in-1 Hub', 1, 59.99),
(6, 13, 'Bluetooth Speaker Pro', 1, 99.99),
(7, 15, 'Gaming Monitor 27"', 1, 399.99),
(7, 3, 'Mechanical Gaming Keyboard', 1, 89.99),
(7, 12, 'LED Desk Lamp', 1, 49.99),
(8, 6, 'Smart Watch Series 5', 1, 199.99),
(9, 11, 'Portable SSD 2TB', 1, 179.99),
(9, 15, 'Gaming Monitor 27"', 1, 399.99),
(9, 3, 'Mechanical Gaming Keyboard', 1, 89.99),
(9, 23, 'Desk Mat XXL', 4, 29.99),
(9, 17, 'Laptop Cooling Pad', 2, 34.99),
(10, 2, 'Wireless Noise-Cancelling Headphones', 1, 249.99),
(10, 14, 'Wireless Charger Pad', 1, 29.99),
(10, 16, 'Webcam Privacy Cover', 5, 9.99),
(11, 9, 'Laptop Backpack 17L', 2, 79.99),
(11, 18, 'Microphone USB Condenser', 2, 79.99),
(11, 25, 'Fitness Tracker Band', 1, 49.99),
(12, 13, 'Bluetooth Speaker Pro', 1, 99.99),
(13, 22, 'External Hard Drive 4TB', 1, 119.99),
(13, 1, 'Laptop Pro X1', 1, 1299.99),
(14, 25, 'Fitness Tracker Band', 2, 49.99),
(15, 15, 'Gaming Monitor 27"', 2, 399.99),
(15, 12, 'LED Desk Lamp', 1, 49.99);
