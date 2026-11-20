const fs = require("node:fs");
const path = require("node:path");
const { search } = require(path.resolve(process.argv[3]));
const cases = require("./cases.json");

function observeBinding(term) {
  const statements = [];
  const adapter = {
    prepare(sql) {
      const executions = [];
      statements.push({ sql, executions });
      return {
        all(...args) {
          executions.push(args);
          return [];
        },
      };
    },
  };
  search(adapter, term);
  return { term, statements };
}

function observeRows() {
  const { DatabaseSync } = require("node:sqlite");
  const db = new DatabaseSync(":memory:");
  try {
    db.exec(fs.readFileSync(path.join(__dirname, "seed.sql"), "utf8"));
    return cases.map(({ term }) => ({
      term,
      ids: search(db, term).map((row) => row.id),
    }));
  } finally {
    db.close();
  }
}

const mode = process.argv[2];
if (mode === "binding") {
  console.log(JSON.stringify(cases.filter((c) => c.ids.length).map((c) => observeBinding(c.term))));
} else if (mode === "sqlite") {
  console.log(JSON.stringify(observeRows()));
} else {
  throw new Error("Expected binding or sqlite");
}
