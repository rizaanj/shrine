// Real mocked unit tests for testCrossUserIDOR function
// Uses Module._load interception to mock @supabase/supabase-js without network calls

const Module = require('module');
const originalLoad = Module._load;

// Mock factory for createClient
function createMockCreateClient(scenario) {
  return function mockCreateClient(url, key) {
    // Helper to create chainable query builder
    const createQueryBuilder = (behavior) => {
      return {
        select: (query) => ({
          eq: (field, value) => {
            if (behavior.eqResult !== undefined) {
              return Promise.resolve(behavior.eqResult);
            }
            return Promise.resolve({ data: [], error: null });
          },
          limit: (n) => Promise.resolve(behavior.selectResult || { data: [], error: null })
        }),
        insert: (data) => ({
          select: () => Promise.resolve(behavior.insertResult || { 
            data: [{ id: 999, ...data }], 
            error: null 
          })
        }),
        delete: () => ({
          eq: (field, value) => Promise.resolve({ error: null })
        })
      };
    };

    // Determine which client behavior based on key
    if (key.includes('service')) {
      return {
        from: (tableName) => createQueryBuilder(scenario.service),
        rpc: (funcName, params) => {
          if (funcName === 'get_tables_rls_status') {
            return Promise.resolve({
              data: scenario.tables || [],
              error: scenario.tablesError || null
            });
          }
          if (funcName === 'get_table_columns') {
            return Promise.resolve({
              data: scenario.columns || [
                { column_name: 'id', data_type: 'integer', is_nullable: 'NO', column_default: 'nextval(...)' },
                { column_name: 'user_id', data_type: 'text', is_nullable: 'YES', column_default: null },
                { column_name: 'content', data_type: 'text', is_nullable: 'YES', column_default: null }
              ],
              error: null
            });
          }
          return Promise.resolve({ data: null, error: null });
        }
      };
    } else if (key.includes('key-a')) {
      return {
        from: (tableName) => createQueryBuilder(scenario.clientA),
        rpc: () => Promise.resolve({ data: null, error: null })
      };
    } else if (key.includes('key-b')) {
      return {
        from: (tableName) => createQueryBuilder(scenario.clientB),
        rpc: () => Promise.resolve({ data: null, error: null })
      };
    }

    // Default mock
    return {
      from: () => createQueryBuilder({ selectResult: { data: [], error: null } }),
      rpc: () => Promise.resolve({ data: null, error: null })
    };
  };
}

// Test trace (a): anonB blocked => 0 IDOR findings
async function testTrace_anonB_blocked() {
  console.log('\n=== Test Trace (a): anonB blocked => 0 IDOR findings ===\n');

  const scenario = {
    tables: [{ table_name: 'users', rls_enabled: true, policy_count: 1 }],
    service: {
      selectResult: { data: [{ id: 1, user_id: 'user-a', content: 'data' }], error: null },
      eqResult: { data: [{ id: 1, user_id: 'user-a', content: 'data' }], error: null }
    },
    clientA: {
      eqResult: { data: [{ id: 1, user_id: 'user-a', content: 'data' }], error: null }
    },
    clientB: {
      eqResult: { data: [], error: null } // RLS blocks clientB
    }
  };

  // Install mock
  Module._load = function(request, parent) {
    if (request === '@supabase/supabase-js') {
      return { createClient: createMockCreateClient(scenario) };
    }
    return originalLoad.apply(this, arguments);
  };

  // Clear cache and require
  delete require.cache[require.resolve('./idorTest')];
  const { testCrossUserIDOR } = require('./idorTest');

  const findings = await testCrossUserIDOR(
    'https://test.supabase.co',
    'anon-key-a',
    'anon-key-b',
    {
      verbose: false,
      allowWriteTest: false,
      serviceRoleKey: 'service-role-key'
    }
  );

  // Restore original
  Module._load = originalLoad;

  console.log('--- Results ---');
  console.log(`Total findings: ${findings.length}`);
  const idorFindings = findings.filter(f => f.type === 'IDOR - Cross-User Read');
  console.log(`IDOR findings: ${idorFindings.length}`);

  if (idorFindings.length === 0) {
    console.log('✓ PASS: No IDOR vulnerability detected (clientB blocked by RLS)');
    return true;
  } else {
    console.log('✗ FAIL: Unexpected IDOR finding');
    console.log(JSON.stringify(idorFindings, null, 2));
    return false;
  }
}

// Test trace (b): anonB leaks => 1 critical finding
async function testTrace_anonB_leaks() {
  console.log('\n\n=== Test Trace (b): anonB leaks => 1 critical finding ===\n');

  const scenario = {
    tables: [{ table_name: 'users', rls_enabled: true, policy_count: 1 }],
    service: {
      selectResult: { data: [{ id: 1, user_id: 'user-a', content: 'data' }], error: null },
      eqResult: { data: [{ id: 1, user_id: 'user-a', content: 'data' }], error: null }
    },
    clientA: {
      eqResult: { data: [{ id: 1, user_id: 'user-a', content: 'sensitive data' }], error: null }
    },
    clientB: {
      eqResult: { data: [{ id: 1, user_id: 'user-a', content: 'sensitive data from user A' }], error: null } // IDOR!
    }
  };

  // Install mock
  Module._load = function(request, parent) {
    if (request === '@supabase/supabase-js') {
      return { createClient: createMockCreateClient(scenario) };
    }
    return originalLoad.apply(this, arguments);
  };

  // Clear cache and require
  delete require.cache[require.resolve('./idorTest')];
  const { testCrossUserIDOR } = require('./idorTest');

  const findings = await testCrossUserIDOR(
    'https://test.supabase.co',
    'anon-key-a',
    'anon-key-b',
    {
      verbose: false,
      allowWriteTest: false,
      serviceRoleKey: 'service-role-key'
    }
  );

  // Restore original
  Module._load = originalLoad;

  console.log('--- Results ---');
  console.log(`Total findings: ${findings.length}`);
  const idorFindings = findings.filter(f => f.type === 'IDOR - Cross-User Read' && f.severity === 'critical');
  console.log(`Critical IDOR findings: ${idorFindings.length}`);

  if (idorFindings.length === 1) {
    const finding = idorFindings[0];
    
    // Verify evidence structure
    const hasProbeId = finding.probeId !== undefined && finding.probeId.includes('id=1');
    const hasEvidence = finding.evidence !== undefined;
    const hasRowCount = hasEvidence && finding.evidence.anonBReturnedRows === 1;
    const hasTableName = finding.message && finding.message.includes('users');
    
    if (hasProbeId && hasEvidence && hasRowCount && hasTableName) {
      console.log('✓ PASS: IDOR vulnerability detected correctly');
      console.log('\nFinding details (truncated):');
      const truncated = {
        type: finding.type,
        severity: finding.severity,
        table: finding.table,
        probeId: finding.probeId,
        evidence: {
          table: finding.evidence.table,
          probeId: finding.evidence.probeId,
          anonBReturnedRows: finding.evidence.anonBReturnedRows,
          sampleData: finding.evidence.sampleData ? '(present)' : '(missing)'
        },
        message: finding.message.substring(0, 80) + '...'
      };
      console.log(JSON.stringify(truncated, null, 2));
      return true;
    } else {
      console.log('✗ FAIL: Finding missing required evidence');
      console.log(`  hasProbeId: ${hasProbeId}`);
      console.log(`  hasEvidence: ${hasEvidence}`);
      console.log(`  hasRowCount: ${hasRowCount}`);
      console.log(`  hasTableName: ${hasTableName}`);
      console.log(JSON.stringify(finding, null, 2));
      return false;
    }
  } else {
    console.log('✗ FAIL: Expected exactly 1 critical IDOR finding');
    console.log(JSON.stringify(findings, null, 2));
    return false;
  }
}

// Test trace (c): identical keys => info finding
async function testTrace_identical_keys() {
  console.log('\n\n=== Test Trace (c): identical keys => info finding ===\n');

  const scenario = {
    tables: [{ table_name: 'users', rls_enabled: true, policy_count: 1 }],
    service: { selectResult: { data: [], error: null } },
    clientA: { eqResult: { data: [], error: null } },
    clientB: { eqResult: { data: [], error: null } }
  };

  // Install mock
  Module._load = function(request, parent) {
    if (request === '@supabase/supabase-js') {
      return { createClient: createMockCreateClient(scenario) };
    }
    return originalLoad.apply(this, arguments);
  };

  // Clear cache and require
  delete require.cache[require.resolve('./idorTest')];
  const { testCrossUserIDOR } = require('./idorTest');

  const findings = await testCrossUserIDOR(
    'https://test.supabase.co',
    'anon-key-same',
    'anon-key-same', // Identical!
    {
      verbose: false,
      allowWriteTest: false,
      serviceRoleKey: 'service-role-key'
    }
  );

  // Restore original
  Module._load = originalLoad;

  console.log('--- Results ---');
  console.log(`Total findings: ${findings.length}`);
  const skipFindings = findings.filter(f => f.type === 'IDOR Test Skipped' && f.severity === 'info');
  const criticalFindings = findings.filter(f => f.severity === 'critical');
  console.log(`Skip findings: ${skipFindings.length}`);
  console.log(`Critical findings: ${criticalFindings.length}`);

  if (skipFindings.length === 1 && criticalFindings.length === 0) {
    console.log('✓ PASS: Identical keys correctly detected and skipped');
    return true;
  } else {
    console.log('✗ FAIL: Expected 1 skip finding and 0 critical findings');
    console.log(JSON.stringify(findings, null, 2));
    return false;
  }
}

// Run all tests
async function runTests() {
  console.log('======================================');
  console.log('Cross-User IDOR Test - Real Mocked Tests');
  console.log('======================================');

  const results = [];
  results.push(await testTrace_anonB_blocked());
  results.push(await testTrace_anonB_leaks());
  results.push(await testTrace_identical_keys());

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

module.exports = { testTrace_anonB_blocked, testTrace_anonB_leaks, testTrace_identical_keys };
