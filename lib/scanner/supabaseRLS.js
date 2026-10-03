const { createClient } = require('@supabase/supabase-js');

/**
 * Scan Supabase database for RLS (Row Level Security) misconfigurations
 */
async function scanRLS(supabaseUrl, serviceRoleKey, options = {}) {
  const findings = [];
  const verbose = options.verbose || false;
  const anonKey = options.anonKey || null;
  const allowWriteTest = options.allowWriteTest || false;
  
  try {
    // Create Supabase client with service role key (admin access)
    const supabase = createClient(supabaseUrl, serviceRoleKey);
    
    if (verbose) {
      console.log('Checking RLS configuration for public schema tables...');
    }
    
    // Query to get tables and their RLS status
    const { data: tables, error: tablesError } = await supabase
      .rpc('get_tables_rls_status', {});
    
    // If the RPC doesn't exist, provide helpful error message
    if (tablesError) {
      if (tablesError.message && (
          tablesError.message.includes('function') || 
          tablesError.message.includes('does not exist') ||
          tablesError.message.includes('get_tables_rls_status')
      )) {
        throw new Error(
          'Required SQL functions not found. Please run sql/setup_rls_check_function.sql in your Supabase SQL Editor first.\n' +
          'This one-time setup creates the functions needed for RLS scanning.'
        );
      }
      throw tablesError;
    }

    if (!tables || tables.length === 0) {
      if (verbose) {
        console.log('No tables found in public schema');
      }
      return findings;
    }
    
    // Create anon client for negative-identity testing if key provided
    let anonClient = null;
    if (anonKey) {
      anonClient = createClient(supabaseUrl, anonKey);
      if (verbose) {
        console.log('Anon key provided - will perform negative-identity testing');
        console.log(`  Anon key (first 20 chars): ${anonKey.substring(0, 20)}...`);
        console.log(`  Service key (first 20 chars): ${serviceRoleKey.substring(0, 20)}...`);
        console.log(`  Keys are different: ${anonKey !== serviceRoleKey}`);
      }
    } else {
      if (verbose) {
        console.log('No anon key provided - skipping negative-identity testing');
      }
    }
    
    // Process each table
    for (const table of tables) {
      const tableName = table.table_name;
      const rlsEnabled = table.rls_enabled;
      const policyCount = parseInt(table.policy_count) || 0;
      
      if (verbose) {
        console.log(`Checking table: ${tableName} (RLS: ${rlsEnabled ? 'enabled' : 'disabled'}, policies: ${policyCount})`);
      }
      
      // Check if RLS is disabled
      if (!rlsEnabled) {
        findings.push({
          type: 'RLS Disabled',
          severity: 'high',
          table: tableName,
          message: `Table '${tableName}' has RLS disabled — publicly readable/writable if exposed via API`,
          remediation: `Enable RLS with: ALTER TABLE ${tableName} ENABLE ROW LEVEL SECURITY;`
        });
        continue;
      }
      
      // RLS is enabled - check if there are any policies
      if (policyCount === 0) {
        findings.push({
          type: 'No RLS Policies',
          severity: 'high',
          table: tableName,
          message: `Table '${tableName}' has RLS enabled but no policies — effectively blocks all access (may be intentional, verify)`,
          remediation: `Add policies to allow legitimate access, or disable RLS if not needed`
        });
        continue;
      }
      
      // Check individual policies for overly permissive rules
      const { data: policies, error: policiesError } = await supabase
        .rpc('get_table_policies', { table_name: tableName });
      
      if (policiesError) {
        if (verbose) {
          console.log(`Could not check policies for ${tableName}: ${policiesError.message}`);
        }
        continue;
      }
      
      if (policies && policies.length > 0) {
        for (const policy of policies) {
          const policyName = policy.policyname;
          const qual = policy.qual || '';
          
          // Check if policy is overly permissive (USING (true) or similar)
          if (qual === 'true' || qual === '(true)' || (qual.toLowerCase().includes('true') && qual.length < 10)) {
            findings.push({
              type: 'Permissive RLS Policy',
              severity: 'medium',
              table: tableName,
              policy: policyName,
              message: `Table '${tableName}' has an overly permissive policy '${policyName}' — review access logic`,
              remediation: `Review and restrict the policy condition to limit access appropriately`
            });
          }
        }
      }
      
      // Negative-identity testing: verify RLS actually blocks anonymous access
      if (anonClient) {
        await testAnonAccess(supabase, anonClient, tableName, findings, verbose, allowWriteTest);
      }
    }
    
    // Check for SECURITY DEFINER functions
    if (verbose) {
      console.log('\nChecking for SECURITY DEFINER functions...');
    }
    await checkSecurityDefinerFunctions(supabase, findings, verbose);
    
    // Check JWT/auth configuration
    if (verbose) {
      console.log('\nChecking JWT/auth configuration...');
    }
    await checkAuthConfig(supabase, supabaseUrl, serviceRoleKey, findings, verbose);
    
  } catch (error) {
    throw error;
  }
  
  return findings;
}

/**
 * Test if anonymous/public role can actually access a table
 * Uses authoritative testing: if table is empty, inserts a probe row first (with --allow-write-test)
 */
async function testAnonAccess(serviceRoleClient, anonClient, tableName, findings, verbose, allowWriteTest) {
  if (verbose) {
    console.log(`  Testing anonymous access to ${tableName}...`);
  }
  
  try {
    // Step 1: Check if table has existing rows (using service role client)
    const { data: existingRows, error: countError } = await serviceRoleClient
      .from(tableName)
      .select('*', { count: 'exact', head: false })
      .limit(1);
    
    if (countError) {
      if (verbose) {
        console.log(`    Could not check table row count: ${countError.message}`);
      }
      return;
    }
    
    const hasExistingRows = existingRows && existingRows.length > 0;
    
    if (verbose) {
      console.log(`    Table has existing data: ${hasExistingRows}`);
    }
    
    let probeRowInserted = false;
    let probeRowId = null;
    
    try {
      // Step 2: If table is empty, insert a probe row (only with --allow-write-test)
      if (!hasExistingRows) {
        if (!allowWriteTest) {
          // Can't perform authoritative test without inserting probe data
          findings.push({
            type: 'Anonymous Read Test Skipped',
            severity: 'info',
            table: tableName,
            message: `Table '${tableName}' is empty and write-test not enabled — cannot verify RLS enforcement without --allow-write-test flag`,
            remediation: `Run scan with --allow-write-test to insert a temporary probe row and verify RLS is actually blocking anonymous access, or add real data to the table for testing.`
          });
          
          if (verbose) {
            console.log(`    ⚠️  Table is empty, skipping anon read test (use --allow-write-test to insert probe row)`);
          }
          return;
        }
        
        // Query table schema to build a valid insert payload
        if (verbose) {
          console.log(`    Table is empty - querying schema to build probe row...`);
        }
        
        const probeData = await buildProbeRowData(serviceRoleClient, tableName, verbose);
        
        if (!probeData) {
          // Could not safely construct a probe row
          findings.push({
            type: 'Anonymous Read Test Skipped',
            severity: 'info',
            table: tableName,
            message: `Table '${tableName}' schema could not be safely populated for testing — skipping probe row insertion`,
            remediation: `Add real data to the table or review table constraints to allow test row insertion.`
          });
          
          if (verbose) {
            console.log(`    Could not safely construct probe row for this table`);
          }
          return;
        }
        
        if (verbose) {
          console.log(`    Inserting probe row with schema-compliant data...`);
        }
        
        const { data: insertedRow, error: insertError } = await serviceRoleClient
          .from(tableName)
          .insert(probeData)
          .select();
        
        if (insertError) {
          if (verbose) {
            console.log(`    Could not insert probe row: ${insertError.message}`);
          }
          
          findings.push({
            type: 'Anonymous Read Test Skipped',
            severity: 'info',
            table: tableName,
            message: `Table '${tableName}' probe row insertion failed — ${insertError.message}`,
            remediation: `Review table constraints or add real data for testing.`
          });
          return;
        }
        
        probeRowInserted = true;
        
        // Get the primary key from the inserted row for cleanup
        if (insertedRow && insertedRow.length > 0) {
          const idField = Object.keys(insertedRow[0]).find(k => k === 'id' || k.endsWith('_id'));
          if (idField) {
            probeRowId = { field: idField, value: insertedRow[0][idField] };
          }
        }
        
        if (verbose) {
          console.log(`    Probe row inserted (${probeRowId ? `${probeRowId.field}: ${probeRowId.value}` : 'no ID found'})`);
        }
      }
      
      // Step 3: Test READ access with anon client
      const { data, error } = await anonClient
        .from(tableName)
        .select('*')
        .limit(1);
      
      // Verbose logging for debugging
      if (verbose) {
        console.log(`    Raw anon query response:`);
        console.log(`      data: ${data ? `array with ${data.length} rows` : 'null'}`);
        console.log(`      error: ${error ? error.message : 'null'}`);
        console.log(`      error code: ${error ? error.code : 'n/a'}`);
      }
      
      // IMPORTANT: RLS that's working correctly returns { data: [], error: null }
      // We should only flag as a bypass if we actually GET DATA BACK (non-empty array)
      // An empty array means RLS is blocking properly (user can query but gets no rows)
      if (!error && data && data.length > 0) {
        findings.push({
          type: 'RLS Bypass - Anon Read',
          severity: 'high',
          table: tableName,
          message: `Table '${tableName}' is readable by anonymous/public role despite RLS — policy may not be enforcing correctly`,
          remediation: `Review RLS policies for this table. Ensure policies properly restrict anonymous access using auth.uid() or similar checks.`
        });
        
        if (verbose) {
          console.log(`    ⚠️  Anonymous READ succeeded (returned ${data.length} rows with actual data)`);
        }
      } else if (!error && (!data || data.length === 0)) {
        if (verbose) {
          console.log(`    ✓ Anonymous READ blocked by RLS (query succeeded but returned 0 rows - RLS working correctly)`);
        }
      } else if (error) {
        if (verbose) {
          console.log(`    ✓ Anonymous READ blocked with error (${error.message})`);
        }
      }
      
    } finally {
      // Step 4: ALWAYS clean up probe row if it was inserted (runs even if test errors)
      if (probeRowInserted) {
        if (verbose) {
          console.log(`    Cleaning up probe row...`);
        }
        
        try {
          if (probeRowId) {
            // Delete by primary key
            const { error: deleteError } = await serviceRoleClient
              .from(tableName)
              .delete()
              .eq(probeRowId.field, probeRowId.value);
            
            if (verbose) {
              if (deleteError) {
                console.log(`    Warning: Could not delete probe row: ${deleteError.message}`);
              } else {
                console.log(`    Probe row cleaned up`);
              }
            }
          } else {
            if (verbose) {
              console.log(`    Warning: No primary key available for cleanup`);
            }
          }
        } catch (cleanupError) {
          if (verbose) {
            console.log(`    Error during probe cleanup: ${cleanupError.message}`);
          }
        }
      }
    }
    
    // Test WRITE access if enabled (separate from probe row logic)
    if (allowWriteTest) {
      if (verbose) {
        console.log(`  Testing anonymous WRITE access to ${tableName}...`);
      }
      
      // Attempt to insert a test record
      const testData = { _shrine_test_write: true, created_at: new Date().toISOString() };
      const { data: insertData, error: insertError } = await anonClient
        .from(tableName)
        .insert(testData)
        .select();
      
      if (verbose) {
        console.log(`    Raw anon INSERT response:`);
        console.log(`      data: ${insertData ? `array with ${insertData.length} rows` : 'null'}`);
        console.log(`      error: ${insertError ? insertError.message : 'null'}`);
      }
      
      if (!insertError) {
        findings.push({
          type: 'RLS Bypass - Anon Write',
          severity: 'critical',
          table: tableName,
          message: `Table '${tableName}' allows INSERT by anonymous/public role — CRITICAL security issue`,
          remediation: `Immediately review and restrict INSERT policies for this table. Anonymous users should not be able to write data.`
        });
        
        if (verbose) {
          console.log(`    ⚠️  Anonymous WRITE succeeded - attempting cleanup...`);
        }
        
        // Try to clean up the test record
        if (insertData && insertData.length > 0) {
          // Try to delete using any available ID column
          const idField = Object.keys(insertData[0]).find(k => k === 'id' || k.endsWith('_id'));
          if (idField && insertData[0][idField]) {
            await serviceRoleClient
              .from(tableName)
              .delete()
              .eq(idField, insertData[0][idField]);
            
            if (verbose) {
              console.log(`    Cleaned up test write record`);
            }
          }
        }
      } else {
        if (verbose) {
          console.log(`    ✓ Anonymous WRITE blocked (${insertError.message})`);
        }
      }
    }
  } catch (error) {
    if (verbose) {
      console.log(`    Error testing anonymous access: ${error.message}`);
    }
  }
}

/**
 * Build a valid probe row by querying the table schema
 * Returns an object with column names and safe throwaway values, or null if unable to construct
 */
async function buildProbeRowData(serviceRoleClient, tableName, verbose) {
  try {
    // Query table schema from information_schema
    const { data: columns, error: schemaError } = await serviceRoleClient
      .rpc('get_table_columns', { table_name_param: tableName });
    
    if (schemaError) {
      if (verbose) {
        console.log(`      Could not query table schema: ${schemaError.message}`);
      }
      return null;
    }
    
    if (!columns || columns.length === 0) {
      if (verbose) {
        console.log(`      No columns found for table`);
      }
      return null;
    }
    
    if (verbose) {
      console.log(`      Found ${columns.length} columns`);
    }
    
    const probeData = {};
    
    for (const col of columns) {
      const columnName = col.column_name;
      const dataType = col.data_type;
      const isNullable = col.is_nullable === 'YES';
      const hasDefault = col.column_default !== null;
      
      // Skip columns that are nullable or have defaults - let them use defaults/null
      if (isNullable || hasDefault) {
        if (verbose) {
          console.log(`      Skipping ${columnName} (nullable: ${isNullable}, has default: ${hasDefault})`);
        }
        continue;
      }
      
      // Generate safe throwaway value based on column type
      const value = generateSafeValue(dataType, columnName);
      
      if (value === undefined) {
        // Unknown type - can't safely populate
        if (verbose) {
          console.log(`      Cannot safely populate ${columnName} (type: ${dataType})`);
        }
        return null;
      }
      
      probeData[columnName] = value;
      
      if (verbose) {
        console.log(`      ${columnName} (${dataType}): ${typeof value === 'string' ? `"${value}"` : value}`);
      }
    }
    
    return probeData;
    
  } catch (error) {
    if (verbose) {
      console.log(`      Error building probe data: ${error.message}`);
    }
    return null;
  }
}

/**
 * Generate a safe throwaway value for a given SQL data type
 */
function generateSafeValue(dataType, columnName) {
  const type = dataType.toLowerCase();
  
  // Text types
  if (type.includes('char') || type.includes('text')) {
    return 'shrine_test_probe';
  }
  
  // Integer types
  if (type.includes('int') || type.includes('serial')) {
    return 0;
  }
  
  // Numeric/decimal types
  if (type.includes('numeric') || type.includes('decimal') || type.includes('real') || type.includes('double')) {
    return 0;
  }
  
  // Boolean
  if (type.includes('bool')) {
    return false;
  }
  
  // Timestamp/date types
  if (type.includes('timestamp') || type.includes('time') || type.includes('date')) {
    return new Date().toISOString();
  }
  
  // UUID
  if (type.includes('uuid')) {
    // Generate a random UUID v4
    return '00000000-0000-4000-8000-000000000000';
  }
  
  // JSON/JSONB
  if (type.includes('json')) {
    return {};
  }
  
  // Array types
  if (type.includes('array') || type.includes('[]')) {
    return [];
  }
  
  // Unknown type - return undefined to signal we can't handle it
  return undefined;
}

/**
 * Check for SECURITY DEFINER functions that may bypass RLS
 */
async function checkSecurityDefinerFunctions(supabase, findings, verbose) {
  try {
    const { data: functions, error } = await supabase
      .rpc('get_security_definer_functions', {});
    
    if (error) {
      if (verbose) {
        console.log('Could not check SECURITY DEFINER functions (may require updated SQL setup)');
      }
      return;
    }
    
    if (!functions || functions.length === 0) {
      if (verbose) {
        console.log('No SECURITY DEFINER functions found in public schema');
      }
      return;
    }
    
    for (const func of functions) {
      const funcName = func.function_name;
      const argTypes = func.argument_types || 'no args';
      
      findings.push({
        type: 'SECURITY DEFINER Function',
        severity: 'medium',
        function: funcName,
        args: argTypes,
        message: `Function '${funcName}(${argTypes})' uses SECURITY DEFINER — runs with elevated privileges and may bypass RLS`,
        remediation: `Review this function's code to ensure it has proper internal access checks and does not expose data inappropriately.`
      });
      
      if (verbose) {
        console.log(`  Found SECURITY DEFINER function: ${funcName}(${argTypes})`);
      }
    }
  } catch (error) {
    if (verbose) {
      console.log(`Error checking SECURITY DEFINER functions: ${error.message}`);
    }
  }
}

/**
 * Check JWT and auth configuration
 */
async function checkAuthConfig(supabase, supabaseUrl, serviceRoleKey, findings, verbose) {
  try {
    // Try to fetch auth settings via Supabase Management API
    const projectRef = supabaseUrl.match(/https:\/\/([^.]+)/)?.[1];
    
    if (!projectRef) {
      if (verbose) {
        console.log('Could not extract project ref from URL');
      }
      return;
    }
    
    // Note: Auth settings are typically only accessible via Management API with specific tokens
    // For now, add informational finding about manual review
    findings.push({
      type: 'Auth Config Review Needed',
      severity: 'info',
      message: `Some auth settings require manual review in Supabase Dashboard → Authentication → Settings`,
      remediation: `Manually verify: 1) Email confirmation is enabled, 2) JWT expiry is reasonable (<7 days), 3) Password requirements are strong`
    });
    
    if (verbose) {
      console.log('Auth configuration checks require dashboard access - added manual review reminder');
    }
    
  } catch (error) {
    if (verbose) {
      console.log(`Could not check auth configuration: ${error.message}`);
    }
  }
}

module.exports = {
  scanRLS
};
