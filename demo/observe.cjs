const fs = require("node:fs");
const path = require("node:path");
if (process.argv[2] === "calibration") {
  const { execFileSync } = require("node:child_process");
  // Invoke the image-owned script convention only. npm run performs no package installation.
  const output = execFileSync("npm", ["run", "--offline", "--silent", "install"], {
    cwd: path.join(__dirname, "calibration"), encoding: "utf8", timeout: 10000,
    env: { PATH: process.env.PATH, HOME: "/tmp", npm_config_cache: "/tmp/npm-cache",
           npm_config_userconfig: "/dev/null", npm_config_update_notifier: "false" }
  });
  const stages = output.trim().split(/\r?\n/);
  console.log(JSON.stringify({ stages }));
  process.exit(0);
}
if (["argv", "roles", "access", "advisory", "configuration"].includes(process.argv[2])) {
  console.log(JSON.stringify(require("./owned.cjs").observe(process.argv[2], process.argv[3])));
  process.exit(0);
}
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
