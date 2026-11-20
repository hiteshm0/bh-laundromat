function search(db, term) {
  return db.prepare(`SELECT id FROM swatches WHERE color = '${term}' ORDER BY id`).all();
}

module.exports = { search };
