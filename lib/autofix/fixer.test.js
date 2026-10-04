const fs = require('fs');
const path = require('path');
const os = require('os');
const { generateFix, applyFix } = require('./fixer');

// Test counter
let testsPassed = 0;
let testsFailed = 0;

function assert(condition, message) {
  if (!condition) {
    console.error(`❌ FAIL: ${message}`);
    testsFailed++;
    throw new Error(message);
  } else {
    console.log(`✓ PASS: ${message}`);
    testsPassed++;
  }
}

function test(name, fn) {
  console.log(`\n[Test] ${name}`);
  try {
    fn();
    console.log(`✓ ${name} PASSED`);
  } catch (err) {
    console.error(`✗ ${name} FAILED: ${err.message}`);
    console.error(err.stack);
  }
}

// Test (a): generateFix with API Missing Auth finding
test('(a) generateFix with API Missing Auth finding', () => {
  const tempFile = path.join(os.tmpdir(), 'test-api-auth.js');
  fs.writeFileSync(tempFile, `app.get('/api/users', (req, res) => {\n  res.json(users);\n});\n`);
  
  const finding = {
    type: 'API Missing Auth',
    file: tempFile,
    line: 1
  };
  
  const fix = generateFix(finding);
  
  assert(fix !== null, 'Fix should not be null');
  assert(fix.fixed === true, 'Fix should be marked as fixed');
  assert(fix.patched.includes('req.user'), 'Patched code should contain req.user check');
  assert(fix.description.includes('auth check'), 'Description should mention auth check');
  assert(fix.original !== fix.patched, 'Original and patched should differ');
  
  fs.unlinkSync(tempFile);
});

// Test (b): generateFix with XSS innerHTML
test('(b) generateFix with XSS innerHTML', () => {
  const tempFile = path.join(os.tmpdir(), 'test-xss.js');
  fs.writeFileSync(tempFile, `element.innerHTML = userInput;\n`);
  
  const finding = {
    type: 'XSS: innerHTML Assignment',
    file: tempFile,
    line: 1
  };
  
  const fix = generateFix(finding);
  
  assert(fix !== null, 'Fix should not be null');
  assert(fix.fixed === true, 'Fix should be marked as fixed');
  assert(fix.patched.includes('textContent'), 'Patched code should contain textContent');
  assert(!fix.patched.includes('innerHTML'), 'Patched code should not contain innerHTML');
  assert(fix.description.includes('textContent'), 'Description should mention textContent');
  
  fs.unlinkSync(tempFile);
});

// Test (c): generateFix with Committed .env
test('(c) generateFix with Committed .env => null (cannot auto-fix)', () => {
  const finding = {
    type: 'Committed .env value',
    file: '.env',
    line: 1
  };
  
  const fix = generateFix(finding);
  
  assert(fix === null, 'Fix should be null for committed .env values (must rotate key)');
});

// Test (d): applyFix with valid fix to temp file + node --check pass
test('(d) applyFix with valid fix to temp file + node --check pass', () => {
  const tempFile = path.join(os.tmpdir(), 'test-apply-valid.js');
  const originalCode = `const x = 5;\nconsole.log(x);\n`;
  fs.writeFileSync(tempFile, originalCode);
  
  const finding = {
    file: tempFile,
    line: 1
  };
  
  const fix = {
    fixed: true,
    original: 'const x = 5;',
    patched: 'const x = 10;',
    description: 'Test fix'
  };
  
  const result = applyFix(finding, fix);
  
  assert(result.applied === true, 'Fix should be applied successfully');
  assert(result.error === null, 'Error should be null on success');
  
  const newContent = fs.readFileSync(tempFile, 'utf-8');
  assert(newContent.includes('const x = 10;'), 'File should contain patched code');
  assert(!newContent.includes('const x = 5;'), 'File should not contain original code');
  
  fs.unlinkSync(tempFile);
});

// Test (e): applyFix with syntax error => rollback
test('(e) applyFix with syntax error => applied=false + rollback', () => {
  const tempFile = path.join(os.tmpdir(), 'test-apply-syntax-error.js');
  const originalCode = `const y = 20;\nconsole.log(y);\n`;
  fs.writeFileSync(tempFile, originalCode);
  
  const finding = {
    file: tempFile,
    line: 1
  };
  
  const fix = {
    fixed: true,
    original: 'const y = 20;',
    patched: 'const y = ;', // Syntax error
    description: 'Test fix with syntax error'
  };
  
  const result = applyFix(finding, fix);
  
  assert(result.applied === false, 'Fix should not be applied due to syntax error');
  assert(result.error !== null, 'Error should not be null on failure');
  assert(result.error.includes('Syntax error') || result.error.includes('syntax'), 'Error should mention syntax error');
  
  // Verify rollback
  const content = fs.readFileSync(tempFile, 'utf-8');
  assert(content.includes('const y = 20;'), 'File should be rolled back to original code');
  assert(!content.includes('const y = ;'), 'File should not contain invalid syntax');
  
  fs.unlinkSync(tempFile);
});

// Run all tests
console.log('\n=== Running fixer.test.js ===\n');

console.log(`\n=== Test Summary ===`);
console.log(`Total tests: ${testsPassed + testsFailed}`);
console.log(`Passed: ${testsPassed}`);
console.log(`Failed: ${testsFailed}`);

if (testsFailed > 0) {
  process.exit(1);
} else {
  console.log('\n✓ All tests passed!');
  process.exit(0);
}
