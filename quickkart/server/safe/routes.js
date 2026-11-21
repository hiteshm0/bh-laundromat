const express = require('express');
const { randomInt } = require('node:crypto');
const { createPaymentVerifier } = require('./payment');

function createSafeRouter(db, authenticate, priceItems) {
  const router = express.Router();
  const attempts = new Map();
  const challenges = new Map();
  const payment = createPaymentVerifier();
  const admin = (req, res, next) => {
    const user = db.prepare('SELECT role FROM users WHERE id = ?').get(req.user.id);
    if (user?.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
    next();
  };
  router.get('/search', (req, res) => {
    res.json(db.prepare('SELECT * FROM products WHERE name LIKE ?').all(`%${String(req.query.q || '')}%`));
  });
  router.get('/admin/users', authenticate, admin, (req, res) => {
    res.json(db.prepare('SELECT id, name, phone, role FROM users').all());
  });
  router.get('/orders/:id', authenticate, (req, res) => {
    const order = db.prepare('SELECT * FROM orders WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
    if (!order) return res.status(404).json({ error: 'Order not found' });
    res.json(order);
  });
  router.post('/auth/send-otp', (req, res) => {
    const phone = req.body.phone;
    if (typeof phone !== 'string' || !/^\d{10}$/.test(phone)) return res.status(400).json({ error: 'Enter a ten-digit phone number' });
    const now = Date.now();
    const keys = [`phone:${phone}`, `ip:${req.ip}`];
    for (const key of keys) {
      const record = attempts.get(key);
      if (record && record.until > now && record.count >= 3) return res.status(429).json({ error: 'Try again later' });
    }
    for (const key of keys) {
      const record = attempts.get(key);
      attempts.set(key, !record || record.until <= now ? { count: 1, until: now + 60000 } : { ...record, count: record.count + 1 });
    }
    challenges.set(phone, { otp: String(randomInt(100000, 1000000)), expires: now + 300000 });
    res.json({ message: 'OTP generated', expiresIn: 300 });
  });
  router.post('/payments/confirm', authenticate, (req, res) => {
    const orderId = Number(req.body.orderId);
    const order = db.prepare('SELECT * FROM orders WHERE id = ? AND user_id = ?').get(orderId, req.user.id);
    if (!order || order.status !== 'Pending payment') return res.status(400).json({ error: 'No pending payment' });
    res.json(payment.confirm(orderId, req.user.id));
  });
  router.post('/checkout', authenticate, (req, res) => {
    if (req.body.orderId) {
      const orderId = Number(req.body.orderId);
      const order = db.prepare('SELECT * FROM orders WHERE id = ? AND user_id = ?').get(orderId, req.user.id);
      if (!order || order.status !== 'Pending payment' || !payment.verify(orderId, req.user.id, req.body.paymentId, req.body.signature)) return res.status(400).json({ error: 'Payment not verified' });
      db.prepare('UPDATE orders SET status = ? WHERE id = ?').run('Paid', orderId);
      return res.json(db.prepare('SELECT * FROM orders WHERE id = ?').get(orderId));
    }
    const priced = priceItems(req.body.items);
    if (!priced) return res.status(400).json({ error: 'Invalid basket' });
    const save = db.transaction(() => {
      const result = db.prepare('INSERT INTO orders (user_id, total, status, created_at) VALUES (?, ?, ?, ?)').run(req.user.id, priced.total, 'Pending payment', new Date().toISOString());
      for (const item of priced.items) db.prepare('INSERT INTO order_items VALUES (?, ?, ?)').run(result.lastInsertRowid, item.productId, item.quantity);
      return db.prepare('SELECT * FROM orders WHERE id = ?').get(result.lastInsertRowid);
    });
    res.status(201).json(save());
  });
  return router;
}

module.exports = { createSafeRouter };
