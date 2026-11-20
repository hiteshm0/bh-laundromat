const assert = require('node:assert/strict');
const { DatabaseSync } = require('node:sqlite');
const { byAisle } = require('./stock.cjs');

const db = new DatabaseSync(':memory:');
db.exec("CREATE TABLE stock (sku TEXT PRIMARY KEY, aisle TEXT)");
db.exec("INSERT INTO stock VALUES ('P3','north'),('P1','north'),('P2','south')");
assert.deepEqual(byAisle(db, 'north').map(row => row.sku), ['P1', 'P3']);
assert.deepEqual(byAisle(db, 'south').map(row => row.sku), ['P2']);
assert.deepEqual(byAisle(db, 'empty').map(row => row.sku), []);
db.close();
