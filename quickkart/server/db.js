const Database = require('better-sqlite3');
const path = require('node:path');

function createDatabase(filename = path.join(__dirname, 'quickkart.sqlite')) {
  const db = new Database(filename);
  db.pragma('foreign_keys = ON');
  db.exec(`
    CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT NOT NULL, category TEXT NOT NULL, price INTEGER NOT NULL, original_price INTEGER NOT NULL, rating REAL NOT NULL, image TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT NOT NULL, phone TEXT UNIQUE NOT NULL, address TEXT NOT NULL DEFAULT '', pan TEXT NOT NULL DEFAULT '', role TEXT NOT NULL DEFAULT 'student');
    CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), total INTEGER NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS order_items (order_id INTEGER NOT NULL REFERENCES orders(id), product_id INTEGER NOT NULL REFERENCES products(id), quantity INTEGER NOT NULL);
  `);
  const seed = db.transaction(() => {
    if (db.prepare('SELECT COUNT(*) AS count FROM products').get().count) return;
    const product = db.prepare('INSERT INTO products VALUES (?, ?, ?, ?, ?, ?, ?)');
    [
      [1, 'Everyday Campus Backpack', 'Bags & Accessories', 899, 1299, 4.8, 'backpack'],
      [2, 'Tune In Wireless Headphones', 'Electronics', 1499, 2499, 4.7, 'headphones'],
      [3, 'The Study Club Notebook Set', 'Stationery', 249, 399, 4.9, 'notebooks'],
      [4, 'Late Night Study Lamp', 'Room Essentials', 699, 999, 4.6, 'lamp'],
      [5, 'Everyday Steel Bottle · 750ml', 'Bags & Accessories', 449, 699, 4.8, 'bottle'],
      [6, 'Type Club Mechanical Keyboard', 'Electronics', 1899, 2999, 4.7, 'keyboard']
    ].forEach(row => product.run(...row));
    const user = db.prepare('INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)');
    [
      [1, 'Aarav Sharma', '9000000001', 'Room 12, Sample College Hostel, Bengaluru', 'FAKEPAN001', 'student'],
      [2, 'Diya Patel', '9000000002', 'Room 24, Sample College Hostel, Pune', 'FAKEPAN002', 'student'],
      [3, 'Kabir Rao', '9000000003', 'Room 36, Sample College Hostel, Delhi', 'FAKEPAN003', 'student'],
      [4, 'Meera Iyer', '9000000004', 'Room 48, Sample College Hostel, Chennai', 'FAKEPAN004', 'student'],
      [5, 'Rohan Das', '9000000005', 'Room 60, Sample College Hostel, Mumbai', 'FAKEPAN005', 'admin']
    ].forEach(row => user.run(...row));
    const order = db.prepare('INSERT INTO orders VALUES (?, ?, ?, ?, ?)');
    const item = db.prepare('INSERT INTO order_items VALUES (?, ?, ?)');
    [[1001, 1, 899, 'Delivered', '2026-11-14'], [1002, 2, 1499, 'Shipped', '2026-11-16'], [1003, 3, 249, 'Delivered', '2026-11-12'], [1004, 4, 699, 'Processing', '2026-11-18'], [1005, 5, 449, 'Delivered', '2026-11-10']].forEach((row, i) => {
      order.run(...row);
      item.run(row[0], i + 1, 1);
    });
  });
  seed();
  return db;
}

module.exports = { createDatabase };
