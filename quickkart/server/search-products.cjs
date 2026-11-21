exports.searchProducts = function searchProducts(db, term) {
  const pattern = `%${term}%`;
  return db.prepare("SELECT * FROM products WHERE name LIKE '" + pattern + "' ORDER BY id").all();
};
