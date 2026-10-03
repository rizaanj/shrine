const jwt = require('jsonwebtoken');

// Test the none algorithm JWT
const testJwtNone = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.";

console.log('Testing none algorithm JWT...');
console.log('Token:', testJwtNone);

try {
  const decoded = jwt.decode(testJwtNone, { complete: true });
  console.log('Decoded:', decoded);
  if (decoded && decoded.header) {
    console.log('Algorithm:', decoded.header.alg);
    console.log('Is none?', decoded.header.alg === 'none');
  }
} catch (e) {
  console.log('Error decoding:', e.message);
}