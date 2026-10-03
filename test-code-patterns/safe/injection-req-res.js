// SAFE: validated/sanitized input
const { body, query, validationResult } = require('express-validator');

app.get('/search', [
  query('q').isString().trim().escape(),
  body('search').isString().trim().escape(),
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  res.send(req.query.q);
  res.render('results', { query: req.query.q });
});