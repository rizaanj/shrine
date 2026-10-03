const jwt = require('jsonwebtoken');

// Create a proper JWT with long expiry
const payload = {
  sub: "1234567890",
  name: "John Doe",
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + (31 * 24 * 60 * 60) // 31 days in future
};

const secret = "test-secret";
const testJwtLongExp = jwt.sign(payload, secret, { algorithm: 'HS256' });

console.log('Testing JWT encoding...');
console.log('Secret:', secret);
console.log('Payload:', JSON.stringify(payload));
console.log('Generated JWT:', testJwtLongExp);

try {
  const decoded = jwt.decode(testJwtLongExp, { complete: true });
  console.log('Decoded JWT:', decoded);
  if (decoded && decoded.payload) {
    console.log('iat:', decoded.payload.iat);
    console.log('exp:', decoded.payload.exp);
    if (decoded.payload.iat && decoded.payload.exp) {
      const expInSeconds = decoded.payload.exp - decoded.payload.iat;
      const expInDays = expInSeconds / (60 * 60 * 24);
      console.log('Expiry in days:', expInDays);
    }
  }
} catch (e) {
  console.log('Error decoding JWT:', e.message);
}