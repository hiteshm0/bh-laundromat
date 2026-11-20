function search(db, term) {
  return db.prepare("SELECT id FROM swatches WHERE color = ? ORDER BY id").all(term);
}

module.exports = { search };
