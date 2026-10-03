// SAFE: SQL parameterized queries
function safeSQL(userInput) {
  db.query('SELECT * FROM users WHERE name = ?', [userInput]);
  db.prepare('SELECT * FROM users WHERE name = ?').get(userInput);
  db.run('UPDATE users SET name = ? WHERE id = ?', [name, id]);
}