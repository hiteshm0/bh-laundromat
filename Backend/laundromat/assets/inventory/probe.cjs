// The service receives a database adapter. Only the harness emits observations.
const { DatabaseSync } = require('node:sqlite');
const { readFileSync } = require('node:fs');
const { byAisle } = require('./stock.cjs');
const spec = JSON.parse(readFileSync('/input/test.json', 'utf8'));
const db = new DatabaseSync(':memory:');
db.exec("CREATE TABLE stock (sku TEXT PRIMARY KEY, aisle TEXT)");
db.exec("INSERT INTO stock VALUES ('P3','north'),('P1','north'),('P2','south')");
const rows = spec.cases.map(({term}) => {
  const calls = [];
  const observed = { prepare(sql) {
    const statement = db.prepare(sql);
    return { all(...args) {
      calls.push({sql, args});
      return statement.all(...args);
    }};
  }};
  const skus = byAisle(observed, term).map(row => row.sku);
  return {term, calls, skus};
});
db.close();
process.stdout.write(JSON.stringify(rows));
