exports.byAisle = function byAisle(db, aisle) {
  return db.prepare("SELECT sku FROM stock WHERE aisle = ? ORDER BY sku").all(aisle);
};
