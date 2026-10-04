const { scanJWT } = require('./lib/scanner/jwtChecker');
const fs = require('fs').promises;
const path = require('path');

// Test with ONLY the none algorithm JWT
const testJwtNone = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.";

async function test() {
  console.log('Testing JWT scanner with none algorithm only...');
  
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
  
  try {
    // Debug: Check if the file contains what we expect
    const fileContent = await fs.readFile(testFilePath, 'utf8');
    console.log('File content:');
    console.log(fileContent);
    console.log('---');
    
    // Test the JWT regex directly
    const jwtPattern = /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g;
    const matches = fileContent.match(jwtPattern);
    console.log('JWT regex matches:', matches);
    
    if (matches) {
      console.log('First match:', matches[0]);
      console.log('Match length:', matches[0].length);
      console.log('Expected length:', testJwtNone.length);
      console.log('Match equals token:', matches[0] === testJwtNone);
    }
    
    // Test placeholder detection
    const lines = fileContent.split('\n');
    console.log('Lines:');
    lines.forEach((line, i) => {
      console.log(`${i}: "${line}"`);
    });
    
    const lineWithToken = lines[1]; // The line with the token (index 1)
    console.log('Line with token:', lineWithToken);
    console.log('Is placeholder?', isPlaceholderJWT(testJwtNone, lineWithToken));
    
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
    try {
      await fs.rm(testDir, { recursive: true, force: true });
    } catch(e) {}
  }
}

function isPlaceholderJWT(token, line) {
  if (!line) return false;
  
  const lowerLine = line.toLowerCase();
  const placeholderPatterns = [
    'example', 'placeholder', 'dummy', 'fake', 'test', 
    'your-token-here', 'sample', 'xxx', 'yyy', 'zzz',
    'jwt-token', 'test-token', 'placeholder-token'
  ];
  
  return placeholderPatterns.some(pattern => lowerLine.includes(pattern));
}

test().catch(console.error);
