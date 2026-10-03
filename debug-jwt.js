const jwt = require('jsonwebtoken');

// Test tokens
const testJwtNone = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.";

// Test with a JWT that has long expiry (more than 30 days from iat)
const iat = Math.floor(Date.now() / 1000); // current timestamp
const exp = iat + (31 * 24 * 60 * 60); // 31 days later
const testJwtLongExp = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOj${exp}fQ.xXPZpA_rRk0JhV8Nqi5V0xfwTEHOfadAo5-S1juKu1E`;

console.log('Testing JWT decoding...');
console.log('None algorithm JWT:', testJwtNone);
console.log('Long expiry JWT:', testJwtLongExp);

try {
  const decodedNone = jwt.decode(testJwtNone, { complete: true });
  console.log('None algorithm decoded:', decodedNone);
  if (decodedNone && decodedNone.header) {
    console.log('Algorithm:', decodedNone.header.alg);
  }
} catch (e) {
  console.log('Error decoding none JWT:', e.message);
}

try {
  const decodedLong = jwt.decode(testJwtLongExp, { complete: true });
  console.log('Long expiry decoded:', decodedLong);
  if (decodedLong && decodedLong.payload) {
    console.log('iat:', decodedLong.payload.iat);
    console.log('exp:', decodedLong.payload.exp);
    if (decodedLong.payload.iat && decodedLong.payload.exp) {
      const expInSeconds = decodedLong.payload.exp - decodedLong.payload.iat;
      const expInDays = expInSeconds / (60 * 60 * 24);
      console.log('Expiry in days:', expInDays);
    }
  }
} catch (e) {
  console.log('Error decoding long JWT:', e.message);
}