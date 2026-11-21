const { DatabaseSync } = require('node:sqlite');
const { readFileSync } = require('node:fs');
const { isDeepStrictEqual } = require('node:util');
const { config, statement, cases } = JSON.parse(readFileSync('/input/plan.json', 'utf8'));
const subject = require('./subject.cjs')[config.export];

const db = new DatabaseSync(':memory:');
const columns = Object.keys(config.columns);
const ident = name => '"' + name + '"';
db.exec('CREATE TABLE ' + ident(config.table) + ' (' +
  columns.map(name => ident(name) + ' ' + config.columns[name]).join(', ') + ')');
const insert = db.prepare('INSERT INTO ' + ident(config.table) + ' VALUES (' +
  columns.map(() => '?').join(', ') + ')');
for (const row of config.rows) insert.run(...columns.map(name => row[name]));

const reference = db.prepare(statement);
const observations = cases.map(({ term }) => {
  const calls = [];
  const observed = {
    prepare(sql) {
      const prepared = db.prepare(sql);
      return {
        all(...args) {
          calls.push({ sql, args });
          return prepared.all(...args);
        }
      };
    }
  };
  const value = config.match === 'contains' ? '%' + term + '%' : term;
  const expected = reference.all(value);
  const actual = subject(observed, term);
  const keys = rows => rows.map(row => row[config.order_by]);
  return {
    term,
    calls,
    rows: keys(actual),
    expected: isDeepStrictEqual(actual, expected),
    bound: calls.length === 1 && calls[0].sql === statement &&
      isDeepStrictEqual(calls[0].args, [value])
  };
});
db.close();
process.stdout.write(JSON.stringify(observations));
