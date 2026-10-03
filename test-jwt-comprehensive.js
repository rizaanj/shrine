const { scanJWT } = require('./lib/scanner/jwtChecker');
const fs = require('fs');
const path = require('path');

// Create a test directory with various JWT scenarios
const testDir = path.join(__dirname, 'test-jwt-scenarios');
if (!fs.existsSync(testDir)) {
  fs.mkdirSync(testDir);
}

// Test 1: None algorithm JWT (should be CRITICAL)
const noneAlgorithmContent = `
const token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
`;

fs.writeFileSync(path.join(testDir, 'none-algo.js'), noneAlgorithmContent);

// Test 2: JWT with secret in same file (should be HIGH)
const secretExposedContent = `
const JWT_SECRET = "my-super-secret-key-12345";
const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
`;

fs.writeFileSync(path.join(testDir, 'secret-exposed.js'), secretExposedContent);

// Test 3: JWT with no expiration (should be MEDIUM)
const noExpirationContent = `
const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
`;

fs.writeFileSync(path.join(testDir, 'no-expiration.js'), noExpirationContent);

// Test 4: JWT with long expiry (should be LOW)
const longExpiryContent = `
const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIywiZXhwIjoyMTQ3NDg0ODAwfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
`;

fs.writeFileSync(path.join(testDir, 'long-expiry.js'), longExpiryContent);

// Test 5: Valid JWT (should be clean)
const validContent = `
const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE3MzQyNzU2MDB9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
`;

fs.writeFileSync(path.join(testDir, 'valid.js'), validContent);

// Run the scanner
console.log('Testing JWT scanner with comprehensive scenarios...\n');
scanJWT({ 
  path: testDir,
  verbose: true, 
  includeTests: false 
}).then(findings => {
  console.log(`\\nFound ${findings.length} JWT issues:`);
  findings.forEach((f, index) => {
    console.log(`${index + 1}. [${f.type}] ${f.file}:${f.line}`);
    console.log(`   ${f.message}`);
    console.log();
  });
  
  // Cleanup
  const files = fs.readdirSync(testDir);
  files.forEach(file => fs.unlinkSync(path.join(testDir, file)));
  fs.rmdirSync(testDir);
}).catch(err => {
  console.error('Error:', err);
});