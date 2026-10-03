const fs = require('fs').promises;
const path = require('path');

// Test with ONLY the none algorithm JWT
const testJwtNone = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.";

// Create a temporary directory and file with JWTs
const testDir = path.join(__dirname, 'jwt-test-temp');
const testFilePath = path.join(testDir, 'jwt-test.js');

// Put the JWT directly in the code (no extra quotes around it in the JS)
const testContent = `
// Test JWT with none algorithm
const token1 = ${JSON.stringify(testJwtNone)};
`;

// Create directory and file
await fs.mkdir(testDir, { recursive: true });
await fs.writeFile(testFilePath, testContent);

// Debug: Check if the file contains what we expect
const fileContent = await fs.readFile(testFilePath, 'utf8');
console.log('File content:');
console.log(JSON.stringify(fileContent)); // Show exact characters
console.log('---');
console.log('Actual content:');
console.log(fileContent);

// Clean up
await fs.rm(testDir, { recursive: true, force: true });