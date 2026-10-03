const { scanJWT } = require('./lib/scanner/jwtChecker');

// Test with ONLY the none algorithm JWT
const testJwtNone = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.";

async function test() {
  console.log('Testing JWT scanner with none algorithm only...');
  
  // Create a temporary directory and file with JWTs
  const fs = require('fs').promises;
  const path = require('path');
  
  const testContent = `
// Test JWT with none algorithm
const token1 = "${testJwtNone}";
`;
  
  const testDir = path.join(__dirname, 'jwt-test-temp');
  const testFilePath = path.join(testDir, 'jwt-test.js');
  
  // Create directory and file
  await fs.mkdir(testDir, { recursive: true });
  await fs.writeFile(testFilePath, testContent);
  
  try {
    const findings = await scanJWT({
      path: testDir,
      verbose: true
    });
    
    console.log(`Found ${findings.length} JWT issues:`);
    findings.forEach((f, i) => {
      console.log(`${i+1}. [${f.type}] Line ${f.line}: ${f.message}`);
    });
  } finally {
    // Clean up
    const fs = require('fs').promises;
    try {
      await fs.rm(testDir, { recursive: true, force: true });
    } catch(e) {}
  }
}

test().catch(console.error);