// Real mocked unit tests for scanApiEndpoints function
// Uses temporary directories and mocked fetch

const fs = require('fs').promises;
const path = require('path');
const os = require('os');

// Mock global fetch
let mockFetchBehavior = null;
const originalFetch = global.fetch;

function setupMockFetch(behavior) {
  mockFetchBehavior = behavior;
  global.fetch = async (url, options) => {
    if (mockFetchBehavior) {
      return mockFetchBehavior(url, options);
    }
    throw new Error('Network request blocked in test');
  };
}

function restoreFetch() {
  global.fetch = originalFetch;
  mockFetchBehavior = null;
}

// Helper to create temp directory with test files
async function createTempDir(files) {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'shrine-api-test-'));
  
  for (const [filePath, content] of Object.entries(files)) {
    const fullPath = path.join(tmpDir, filePath);
    await fs.mkdir(path.dirname(fullPath), { recursive: true });
    await fs.writeFile(fullPath, content);
  }
  
  return tmpDir;
}

// Helper to cleanup temp directory
async function cleanupTempDir(tmpDir) {
  try {
    await fs.rm(tmpDir, { recursive: true, force: true });
  } catch (err) {
    // Ignore cleanup errors
  }
}

// Test trace (a): admin route with no auth => 1 Open Admin Route critical
async function testTrace_admin_no_auth() {
  console.log('\n=== Test Trace (a): admin route with no auth => 1 Open Admin Route critical ===\n');
  
  const tmpDir = await createTempDir({
    'routes/api/admin.js': `
// Admin route
app.get('/api/admin', (req, res) => {
  res.json({ users: getAllUsers() });
});
`
  });

  try {
    const { scanApiEndpoints } = require('./apiTester');
    const findings = await scanApiEndpoints(tmpDir, { verbose: false });

    console.log('--- Results ---');
    console.log(`Total findings: ${findings.length}`);
    const adminFindings = findings.filter(f => f.type === 'Open Admin Route' && f.severity === 'critical');
    console.log(`Open Admin Route findings: ${adminFindings.length}`);

    if (adminFindings.length === 1) {
      const finding = adminFindings[0];
      console.log('✓ PASS: Open admin route detected correctly');
      console.log('\nFinding details:');
      console.log(JSON.stringify({
        type: finding.type,
        severity: finding.severity,
        route: finding.route,
        file: finding.file
      }, null, 2));
      return true;
    } else {
      console.log('✗ FAIL: Expected 1 Open Admin Route finding');
      console.log(JSON.stringify(findings, null, 2));
      return false;
    }
  } finally {
    await cleanupTempDir(tmpDir);
  }
}

// Test trace (b): route with auth keyword => 0 Missing Auth
async function testTrace_route_with_auth() {
  console.log('\n\n=== Test Trace (b): route with auth keyword => 0 Missing Auth ===\n');
  
  const tmpDir = await createTempDir({
    'app/api/public/route.js': `
import { verifyToken } from '@/lib/auth';

export async function GET(request) {
  const token = verifyToken(request);
  if (!token) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }
  return Response.json({ data: 'protected' });
}
`
  });

  try {
    const { scanApiEndpoints } = require('./apiTester');
    const findings = await scanApiEndpoints(tmpDir, { verbose: false });

    console.log('--- Results ---');
    console.log(`Total findings: ${findings.length}`);
    const missingAuthFindings = findings.filter(f => f.type === 'API Missing Auth');
    console.log(`Missing Auth findings: ${missingAuthFindings.length}`);

    if (missingAuthFindings.length === 0) {
      console.log('✓ PASS: Auth-protected route correctly identified');
      return true;
    } else {
      console.log('✗ FAIL: Expected 0 Missing Auth findings for protected route');
      console.log(JSON.stringify(missingAuthFindings, null, 2));
      return false;
    }
  } finally {
    await cleanupTempDir(tmpDir);
  }
}

// Test trace (c): mock fetch returns 200 => 1 Anon Access with evidence
async function testTrace_fetch_200() {
  console.log('\n\n=== Test Trace (c): mock fetch returns 200 => 1 Anon Access ===\n');
  
  const tmpDir = await createTempDir({
    'pages/api/open.js': `
export default function handler(req, res) {
  res.json({ data: 'public' });
}
`
  });

  try {
    // Mock fetch to return 200
    setupMockFetch(async (url, options) => {
      return {
        status: 200,
        text: async () => '{"data":"sensitive information"}'
      };
    });

    const { scanApiEndpoints } = require('./apiTester');
    const findings = await scanApiEndpoints(tmpDir, { 
      verbose: false, 
      apiUrl: 'https://test.example.com' 
    });

    console.log('--- Results ---');
    console.log(`Total findings: ${findings.length}`);
    const anonAccessFindings = findings.filter(f => f.type === 'API Anon Access');
    console.log(`Anon Access findings: ${anonAccessFindings.length}`);

    if (anonAccessFindings.length >= 1) {
      const finding = anonAccessFindings[0];
      const hasStatus = finding.evidence && finding.evidence.status === 200;
      const hasBody = finding.evidence && finding.evidence.bodyTruncated;
      
      if (hasStatus && hasBody) {
        console.log('✓ PASS: Anonymous access detected with proper evidence');
        console.log('\nFinding details:');
        console.log(JSON.stringify({
          type: finding.type,
          severity: finding.severity,
          route: finding.route,
          evidence: {
            status: finding.evidence.status,
            bodyTruncated: finding.evidence.bodyTruncated.substring(0, 50) + '...'
          }
        }, null, 2));
        return true;
      } else {
        console.log('✗ FAIL: Finding missing required evidence');
        console.log(`  hasStatus: ${hasStatus}`);
        console.log(`  hasBody: ${hasBody}`);
        return false;
      }
    } else {
      console.log('✗ FAIL: Expected at least 1 Anon Access finding');
      console.log(JSON.stringify(findings, null, 2));
      return false;
    }
  } finally {
    restoreFetch();
    await cleanupTempDir(tmpDir);
  }
}

// Test trace (d): mock fetch throws => 0 crash and warn
async function testTrace_fetch_error() {
  console.log('\n\n=== Test Trace (d): mock fetch throws => no crash ===\n');
  
  const tmpDir = await createTempDir({
    'pages/api/test.js': `
export default function handler(req, res) {
  res.json({ ok: true });
}
`
  });

  try {
    // Mock fetch to throw error
    setupMockFetch(async (url, options) => {
      throw new Error('Network error');
    });

    // Capture console.warn
    const warnings = [];
    const originalWarn = console.warn;
    console.warn = (...args) => {
      warnings.push(args.join(' '));
    };

    const { scanApiEndpoints } = require('./apiTester');
    const findings = await scanApiEndpoints(tmpDir, { 
      verbose: false, 
      apiUrl: 'https://test.example.com' 
    });

    console.warn = originalWarn;

    console.log('--- Results ---');
    console.log(`Total findings: ${findings.length}`);
    console.log(`Warnings logged: ${warnings.length}`);
    console.log(`Sample warning: ${warnings[0] || 'none'}`);

    if (warnings.length > 0 && warnings[0].includes('API probe skipped')) {
      console.log('✓ PASS: Network error handled gracefully with warning');
      return true;
    } else {
      console.log('✗ FAIL: Expected warning for network error');
      console.log('Warnings:', warnings);
      return false;
    }
  } catch (error) {
    console.log('✗ FAIL: Scanner crashed on network error');
    console.log(error.message);
    return false;
  } finally {
    restoreFetch();
    await cleanupTempDir(tmpDir);
  }
}

// Run all tests
async function runTests() {
  console.log('======================================');
  console.log('API Endpoint Tester - Real Mocked Tests');
  console.log('======================================');

  const results = [];
  results.push(await testTrace_admin_no_auth());
  results.push(await testTrace_route_with_auth());
  results.push(await testTrace_fetch_200());
  results.push(await testTrace_fetch_error());

  console.log('\n\n======================================');
  console.log('Test Summary');
  console.log('======================================');
  console.log(`Passed: ${results.filter(r => r).length}/${results.length}`);
  console.log(`Failed: ${results.filter(r => !r).length}/${results.length}`);
  console.log('======================================\n');

  process.exit(results.every(r => r) ? 0 : 1);
}

// Run if executed directly
if (require.main === module) {
  runTests().catch(err => {
    console.error('Test error:', err);
    process.exit(1);
  });
}

module.exports = { testTrace_admin_no_auth, testTrace_route_with_auth, testTrace_fetch_200, testTrace_fetch_error };
