const { sendAlert } = require('./webhook');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const testDir = path.join(__dirname, '.test-cache');
const testCacheDir = path.join(testDir, 'alerts');

function cleanup() {
  if (fs.existsSync(testDir)) {
    fs.rmSync(testDir, { recursive: true, force: true });
  }
}

function createFinding(overrides = {}) {
  return {
    type: 'AWS_SECRET_KEY',
    severity: 'critical',
    file: 'config.js',
    line: 10,
    message: 'AWS secret key detected',
    evidence: { bodyTruncated: 'AKIAIOSFODNN7EXAMPLE...' },
    ...overrides
  };
}

async function runTests() {
  cleanup();
  fs.mkdirSync(testCacheDir, { recursive: true });

  let passed = 0;
  let failed = 0;

  const originalFetch = global.fetch;
  const originalConsoleWarn = console.warn;
  const warns = [];

  console.warn = (msg) => warns.push(msg);

  // Test (a): sendAlert with mocked fetch 200 + no cached hash => expect true, payload contains severity/type/file/redacted NOT raw match
  try {
    global.fetch = async (url, options) => {
      const body = JSON.parse(options.body);
      if (!body.severity || !body.type || !body.file || body.redacted === undefined) {
        throw new Error('Payload missing required fields');
      }
      if (body.message.includes('AKIAIOSFODNN7EXAMPLE')) {
        throw new Error('Raw secret in payload');
      }
      if (body.redacted.length > 100) {
        throw new Error('Redacted too long');
      }
      return { ok: true };
    };

    const finding = createFinding();
    const result = await sendAlert(finding, { webhookUrl: 'https://webhook.test', verbose: false, cacheDir: testCacheDir });
    
    if (result === true) {
      console.log('Test (a) PASSED: sendAlert returns true, payload validated');
      passed++;
    } else {
      console.log('Test (a) FAILED: expected true, got', result);
      failed++;
    }
  } catch (e) {
    console.log('Test (a) FAILED:', e.message);
    failed++;
  }

  // Test (b): sendAlert same finding twice within 60min => first true, second false (rate-limited)
  try {
    let callCount = 0;
    global.fetch = async () => {
      callCount++;
      return { ok: true };
    };

    const finding = createFinding({ type: 'GITHUB_TOKEN', file: 'auth.js', line: 5 });
    const result1 = await sendAlert(finding, { webhookUrl: 'https://webhook.test', verbose: false, cacheDir: testCacheDir });
    const result2 = await sendAlert(finding, { webhookUrl: 'https://webhook.test', verbose: false, cacheDir: testCacheDir });

    if (result1 === true && result2 === false) {
      console.log('Test (b) PASSED: first true, second false (rate-limited)');
      passed++;
    } else {
      console.log('Test (b) FAILED: expected true then false, got', result1, result2);
      failed++;
    }
  } catch (e) {
    console.log('Test (b) FAILED:', e.message);
    failed++;
  }

  // Test (c): sendAlert with mocked fetch throw => expect false, console.warn 'Alert skipped', no crash
  try {
    warns.length = 0;
    global.fetch = async () => { throw new Error('Network error'); };

    const finding = createFinding({ type: 'JWT_SECRET', file: 'jwt.js', line: 20 });
    const result = await sendAlert(finding, { webhookUrl: 'https://webhook.test', verbose: false, cacheDir: testCacheDir });

    if (result === false && warns.some(w => w.includes('Alert skipped'))) {
      console.log('Test (c) PASSED: returns false, warns, no crash');
      passed++;
    } else {
      console.log('Test (c) FAILED: expected false + warn, got result=', result, 'warns=', warns);
      failed++;
    }
  } catch (e) {
    console.log('Test (c) FAILED (threw):', e.message);
    failed++;
  }

  // Test (d): payload verification: redacted max 100 chars, no raw secrets
  try {
    let capturedPayload = null;
    global.fetch = async (url, options) => {
      capturedPayload = JSON.parse(options.body);
      return { ok: true };
    };

    const longEvidence = 'x'.repeat(150);
    const finding = createFinding({ 
      type: 'LONG_SECRET_TEST',
      evidence: { bodyTruncated: longEvidence },
      redacted: undefined
    });
    await sendAlert(finding, { webhookUrl: 'https://webhook.test', verbose: false, cacheDir: testCacheDir });

    if (capturedPayload && capturedPayload.redacted.length <= 100 && 
        !capturedPayload.redacted.includes('AKIAIOSFODNN7EXAMPLE') &&
        capturedPayload.redacted === longEvidence.slice(0, 100)) {
      console.log('Test (d) PASSED: redacted max 100 chars, no raw secrets');
      passed++;
    } else {
      console.log('Test (d) FAILED: redacted=', capturedPayload?.redacted);
      failed++;
    }
  } catch (e) {
    console.log('Test (d) FAILED:', e.message);
    failed++;
  }

  global.fetch = originalFetch;
  console.warn = originalConsoleWarn;
  cleanup();

  console.log(`\nResults: ${passed} passed, ${failed} failed`);
  process.exit(failed > 0 ? 1 : 0);
}

runTests();