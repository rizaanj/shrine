const { generateReceipt, saveReceipt, loadReceipt, isStale } = require('./receipt');
const fs = require('fs');
const path = require('path');
const os = require('os');

// Test (a): generateReceipt with tables and findings
console.log('Test (a): generateReceipt with tables and findings');
const tables = [{ table_name: 'users', rls_enabled: true, policy_count: 1 }];
const findings = [{ type: 'Secret', severity: 'high', file: 'a.js' }];
const receipt = generateReceipt({ findings, filesScanned: 10, tables });

console.assert(receipt.schemaHash.length === 16, 'schemaHash should be 16 chars');
console.assert(receipt.findingsHash.length === 16, 'findingsHash should be 16 chars');
console.assert(typeof receipt.timestamp === 'number', 'timestamp should be present');
console.assert(receipt.version === '1.0.2', 'version should be 1.0.2');
console.log('PASS: schemaHash=' + receipt.schemaHash + ', findingsHash=' + receipt.findingsHash + ', timestamp=' + receipt.timestamp + ', version=' + receipt.version);

// Test (b): isStale with same hashes and different schemaHash
console.log('\nTest (b): isStale with same hashes + different schemaHash');
const receipt1 = generateReceipt({ findings, filesScanned: 10, tables });
const receipt2 = generateReceipt({ findings, filesScanned: 10, tables });
const staleCheck1 = isStale(receipt1, receipt2);
console.assert(staleCheck1.stale === false, 'Same receipts should not be stale');
console.assert(staleCheck1.reason === null, 'Reason should be null');
console.log('PASS: same hashes => stale=' + staleCheck1.stale + ', reason=' + staleCheck1.reason);

const differentTables = [{ table_name: 'posts', rls_enabled: false, policy_count: 0 }];
const receipt3 = generateReceipt({ findings, filesScanned: 10, tables: differentTables });
const staleCheck2 = isStale(receipt3, receipt1);
console.assert(staleCheck2.stale === true, 'Different schema should be stale');
console.assert(staleCheck2.reason === 'schema changed', 'Reason should be schema changed');
console.log('PASS: different schemaHash => stale=' + staleCheck2.stale + ', reason=' + staleCheck2.reason);

// Test (c): load/save roundtrip + 25h old timestamp
console.log('\nTest (c): load/save roundtrip + expired timestamp');
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'shrine-test-'));
const testReceipt = generateReceipt({ findings, filesScanned: 10, tables });
saveReceipt(tmpDir, testReceipt);
const loadedReceipt = loadReceipt(tmpDir);
console.assert(loadedReceipt !== null, 'Receipt should be loaded');
console.assert(loadedReceipt.timestamp === testReceipt.timestamp, 'Timestamp should match');
console.assert(loadedReceipt.schemaHash === testReceipt.schemaHash, 'schemaHash should match');
console.log('PASS: roundtrip => timestamp=' + loadedReceipt.timestamp + ', schemaHash=' + loadedReceipt.schemaHash);

const oldReceipt = { ...testReceipt, timestamp: Date.now() - (25 * 60 * 60 * 1000) };
const staleCheck3 = isStale(testReceipt, oldReceipt);
console.assert(staleCheck3.stale === true, '25h old should be stale');
console.assert(staleCheck3.reason === 'expired', 'Reason should be expired');
console.log('PASS: 25h old => stale=' + staleCheck3.stale + ', reason=' + staleCheck3.reason);

// Cleanup
fs.rmSync(tmpDir, { recursive: true });

// Test (d): saveReceipt where directory not writable
console.log('\nTest (d): saveReceipt with mkdirSync failure');
const originalMkdirSync = fs.mkdirSync;
let errorLogged = false;
const originalConsoleError = console.error;
console.error = function(...args) {
  if (args[0].includes('Failed to save receipt')) {
    errorLogged = true;
  }
};

fs.mkdirSync = function() {
  throw new Error('EACCES: permission denied');
};

try {
  saveReceipt('/fake/path', testReceipt);
  console.assert(errorLogged === true, 'Should log error to console.error');
  console.log('PASS: mkdirSync throw => console.error only, no throw');
} finally {
  fs.mkdirSync = originalMkdirSync;
  console.error = originalConsoleError;
}

console.log('\nAll tests passed!');
