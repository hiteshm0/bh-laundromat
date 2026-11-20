// The controller accepts exact, reviewed fixture bytes only. This observer never runs a shell or model.
const fs = require("node:fs");
const vm = require("node:vm");

function observe(test, file) {
  const context = { exports: {}, process: {env: {CATALOG_KEY: "fixture setting"}} };
  const src = fs.readFileSync(file, "utf8");
  if (test === "advisory") {
    const resolved = JSON.parse(src).packages["node_modules/lodash"].version;
    const ids = require("./cases.json").map(c => c.ids);
    // Exercise the ordinary catalog search with the selected lock metadata present.
    const { DatabaseSync } = require("node:sqlite");
    const db = new DatabaseSync(":memory:");
    try {
      db.exec(fs.readFileSync(__dirname + "/seed.sql", "utf8"));
      const actual = ["amber", "indigo", "jade"].map(term =>
        db.prepare("SELECT id FROM swatches WHERE color = ? ORDER BY id").all(term).map(r => r.id));
      return {resolved, regression: JSON.stringify(ids) === JSON.stringify(actual), actual};
    } finally { db.close(); }
  }
  if (test === "access") {
    let handlers;
    context.router = {post: (route, ...chain) => { if (route === "/orders") handlers = chain; }};
    context.requireUser = (loggedIn, next) => loggedIn ? next() : 401;
    context.saveOrder = () => 200;
    vm.runInNewContext(src, context);
    return { decisions: [false, true].map(user => {
      let i = 0;
      function next() { return handlers[i++](user, next); }
      return next();
    }) };
  }
  vm.runInNewContext(src, context);
  if (test === "configuration") return {reads_environment: context.exports.key() === "fixture setting"};
  if (test === "argv") return {calls: ["amber", "indigo blue"].map(label =>
    context.exports.run((...args) => args, label))};
  if (test === "roles") return {messages: context.exports.messages("ordinary catalog text")};
  throw Error("Unknown test");
}
module.exports = { observe };
