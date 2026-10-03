// VULNERABLE: unsanitized req.query/req.body in res.send/render
app.get('/search', (req, res) => {
  res.send(req.query.q);
  res.send(req.body.search);
  res.render('results', { query: req.query.q });
  res.json({ result: req.body.data });
  res.jsonp(req.params.id);
});

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