const { generateRevokeSteps, assessUserImpact, generateBreachNotice } = require('./response');

function createFinding(overrides = {}) {
  return {
    type: 'API Key',
    severity: 'critical',
    file: 'config.js',
    line: 10,
    ...overrides
  };
}

async function runTests() {
  let passed = 0;
  let failed = 0;

  // Test (a): generateRevokeSteps with [{type:'API Key',severity:'critical'}] => expect array contains 'Revoke key', deduplicates
  try {
    const findings = [
      createFinding({ type: 'API Key', severity: 'critical' }),
      createFinding({ type: 'API Key', severity: 'critical' }), // duplicate
      createFinding({ type: 'Database Exposed', severity: 'high' })
    ];
    const steps = generateRevokeSteps(findings);
    
    const hasRevokeKey = steps.some(s => s.includes('Revoke key'));
    const uniqueSteps = new Set(steps).size === steps.length;
    
    if (hasRevokeKey && uniqueSteps) {
      console.log('Test (a) PASSED: contains revoke steps, deduplicated');
      passed++;
    } else {
      console.log('Test (a) FAILED: steps=', steps);
      failed++;
    }
  } catch (e) {
    console.log('Test (a) FAILED:', e.message);
    failed++;
  }

  // Test (b): assessUserImpact with 15 findings + 1 critical => expect severity='critical', affectedUsers present, summary contains '15 security issues'
  try {
    const findings = Array(15).fill().map((_, i) => createFinding({ 
      type: `Test ${i}`, 
      severity: i === 0 ? 'critical' : 'low',
      file: `file${i}.js`
    }));
    const impact = assessUserImpact(findings, { filesScanned: 100, tables: [] });
    
    if (impact.severity === 'critical' && 
        impact.affectedUsers && 
        impact.summary.includes('15 security issues')) {
      console.log('Test (b) PASSED: severity=critical, summary correct');
      passed++;
    } else {
      console.log('Test (b) FAILED:', impact);
      failed++;
    }
  } catch (e) {
    console.log('Test (b) FAILED:', e.message);
    failed++;
  }

  // Test (c): assessUserImpact with IDOR critical => expect affectedUsers='all'
  try {
    const findings = [createFinding({ type: 'IDOR', severity: 'critical', file: 'api.js' })];
    const impact = assessUserImpact(findings, { filesScanned: 10, tables: [] });
    
    if (impact.affectedUsers === 'all') {
      console.log('Test (c) PASSED: affectedUsers=all for IDOR critical');
      passed++;
    } else {
      console.log('Test (c) FAILED:', impact);
      failed++;
    }
  } catch (e) {
    console.log('Test (c) FAILED:', e.message);
    failed++;
  }

  // Test (d): generateBreachNotice with impact => expect markdown contains 'Security Incident Notice', date, summary, no raw findings
  try {
    const impact = {
      severity: 'critical',
      affectedUsers: 'all',
      dataExposed: ['users', 'orders'],
      summary: '2 security issues detected. Severity: critical. Potential data exposure in 2 locations.'
    };
    const notice = generateBreachNotice(impact, { companyName: 'Acme Corp' });
    
    const hasTitle = notice.includes('Security Incident Notice');
    const hasDate = notice.includes(new Date().toISOString().split('T')[0]);
    const hasSummary = notice.includes(impact.summary);
    const noRawFindings = !notice.includes('config.js') && !notice.includes('api.js');
    const hasContact = notice.includes('security@acmecorp.com');
    
    if (hasTitle && hasDate && hasSummary && noRawFindings && hasContact) {
      console.log('Test (d) PASSED: notice contains required elements, no raw findings');
      passed++;
    } else {
      console.log('Test (d) FAILED: notice=', notice);
      failed++;
    }
  } catch (e) {
    console.log('Test (d) FAILED:', e.message);
    failed++;
  }

  console.log(`\nResults: ${passed} passed, ${failed} failed`);
  process.exit(failed > 0 ? 1 : 0);
}

runTests();