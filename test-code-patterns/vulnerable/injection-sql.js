// VULNERABLE: SQL concatenation/template literal
const db = require('db');

function vulnerableSQL(userInput) {
  db.query('SELECT * FROM users WHERE name = ' + userInput);
  db.query(`SELECT * FROM users WHERE name = '${userInput}'`);
  db.execute('UPDATE users SET name = ' + name + ' WHERE id = ' + id);
  db.run(`DELETE FROM users WHERE id = ${id}`);
  db.all('SELECT * FROM ' + tableName);
  db.get('SELECT * FROM users WHERE email = ' + email);
}

// SAFE: SQL parameterized queries
function safeSQL(userInput) {
  db.query('SELECT * FROM users WHERE name = ?', [userInput]);
  db.prepare('SELECT * FROM users WHERE name = ?').get(userInput);
  db.run('UPDATE users SET name = ? WHERE id = ?', [name, id]);
}