const { createClient } = require('@supabase/supabase-js');

/**
 * Test for cross-user IDOR vulnerabilities
 * Uses two anonymous clients to verify RLS properly isolates user data
 */
async function testCrossUserIDOR(supabaseUrl, anonKeyA, anonKeyB, options = {}) {
  const findings = [];
  const verbose = options.verbose || false;
  
  // Validate inputs
  if (!supabaseUrl || !anonKeyA || !anonKeyB) {
    if (verbose) {
      console.log('Cross-user IDOR test: missing required parameters (supabaseUrl, anonKeyA, anonKeyB)');
    }
    return findings;
  }
  
  // Verify keys are different
  if (anonKeyA === anonKeyB) {
    if (verbose) {
      console.log('Warning: anonKeyA and anonKeyB are identical - skipping IDOR test');
    }
    findings.push({
      type: 'IDOR Test Skipped',
      severity: 'info',
      message: 'Cross-user IDOR test skipped: provided anon keys are identical',
      remediation: 'Provide two different anonymous/authenticated user keys to test cross-user data isolation'
    });
    return findings;
  }
  
  if (verbose) {
    console.log('\n=== Cross-User IDOR Test ===');
    console.log(`Supabase URL: ${supabaseUrl}`);
    console.log(`Anon Key A (first 20 chars): ${anonKeyA.substring(0, 20)}...`);
    console.log(`Anon Key B (first 20 chars): ${anonKeyB.substring(0, 20)}...`);
    console.log(`Allow write test: ${options.allowWriteTest === true}`);
  }
  
  try {
    // Create two anonymous clients
    const clientA = createClient(supabaseUrl, anonKeyA);
    const clientB = createClient(supabaseUrl, anonKeyB);
    
    // Create service role client for cleanup (need to get service key from options)
    let serviceClient = null;
    if (options.serviceRoleKey) {
      serviceClient = createClient(supabaseUrl, options.serviceRoleKey);
    }
    
    if (verbose) {
      console.log('Created two anonymous clients for cross-user testing\n');
    }
    
    // Get list of tables
    if (!serviceClient) {
      if (verbose) {
        console.log('Warning: no service role key provided - cannot query table list');
      }
      findings.push({
        type: 'IDOR Test Skipped',
        severity: 'info',
        message: 'Cross-user IDOR test requires service role key to query table list',
        remediation: 'Provide service role key via options.serviceRoleKey'
      });
      return findings;
    }
    
    const { data: tables, error: tablesError } = await serviceClient
      .rpc('get_tables_rls_status', {});
    
    if (tablesError) {
      if (tablesError.message && tablesError.message.includes('get_tables_rls_status')) {
        if (verbose) {
          console.log('Required RPC function get_tables_rls_status not found - skipping IDOR test');
        }
        findings.push({
          type: 'IDOR Test Skipped',
          severity: 'info',
          message: 'Cross-user IDOR test requires get_tables_rls_status RPC function',
          remediation: 'Run sql/setup_rls_check_function.sql in your Supabase SQL Editor'
        });
        return findings;
      }
      throw tablesError;
    }
    
    if (!tables || tables.length === 0) {
      if (verbose) {
        console.log('No tables found in public schema');
      }
      return findings;
    }
    
    if (verbose) {
      console.log(`Found ${tables.length} tables to test\n`);
    }
    
    // Test each table
    for (const table of tables) {
      const tableName = table.table_name;
      
      if (verbose) {
        console.log(`Testing table: ${tableName}`);
      }
      
      await testTableForIDOR(
        serviceClient,
        clientA,
        clientB,
        tableName,
        findings,
        verbose,
        options.allowWriteTest === true
      );
      
      if (verbose) {
        console.log(''); // Blank line between tables
      }
    }
    
  } catch (error) {
    if (verbose) {
      console.log(`Cross-user IDOR test error: ${error.message}`);
    }
    findings.push({
      type: 'IDOR Test Error',
      severity: 'info',
      message: `Cross-user IDOR test encountered error: ${error.message}`,
      remediation: 'Review error and ensure database setup is correct'
    });
  }
  
  return findings;
}

/**
 * Test a single table for cross-user IDOR vulnerability
 */
async function testTableForIDOR(serviceClient, clientA, clientB, tableName, findings, verbose, allowWriteTest) {
  let probeRowInserted = false;
  let probeRowId = null;
  
  try {
    // Step 1: Check if table has existing rows
    const { data: existingRows, error: countError } = await serviceClient
      .from(tableName)
      .select('*', { count: 'exact', head: false })
      .limit(1);
    
    if (countError) {
      if (verbose) {
        console.log(`  Could not check table row count: ${countError.message}`);
      }
      return;
    }
    
    const hasExistingRows = existingRows && existingRows.length > 0;
    
    if (verbose) {
      console.log(`  Table has existing data: ${hasExistingRows}`);
    }
    
    // Step 2: If table is empty, check if we can insert probe row
    if (!hasExistingRows) {
      if (!allowWriteTest) {
        // Skip with info finding
        findings.push({
          type: 'IDOR Test Skipped',
          severity: 'info',
          table: tableName,
          message: `Cross-user IDOR test skipped for '${tableName}' - table is empty and write test not enabled`,
          remediation: `Run scan with --allow-write-test to insert temporary probe row, or add real data to the table for testing`
        });
        
        if (verbose) {
          console.log(`  Skipping: table is empty and --allow-write-test not enabled`);
        }
        return;
      }
      
      // Build probe row
      if (verbose) {
        console.log(`  Table is empty - building probe row for insertion`);
      }
      
      const probeData = await buildProbeRowData(serviceClient, tableName, verbose);
      
      if (!probeData) {
        findings.push({
          type: 'IDOR Test Skipped',
          severity: 'info',
          table: tableName,
          message: `Cross-user IDOR test skipped for '${tableName}' - could not construct valid probe row`,
          remediation: `Add real data to the table or review table constraints`
        });
        
        if (verbose) {
          console.log(`  Skipping: could not construct probe row`);
        }
        return;
      }
      
      // Insert probe row via serviceClient (to avoid RLS block on anon insert)
      if (verbose) {
        console.log(`  Inserting probe row via service client...`);
      }
      
      const { data: insertedRow, error: insertError } = await serviceClient
        .from(tableName)
        .insert(probeData)
        .select();
      
      if (insertError) {
        if (verbose) {
          console.log(`  Could not insert probe row: ${insertError.message}`);
        }
        
        findings.push({
          type: 'IDOR Test Skipped',
          severity: 'info',
          table: tableName,
          message: `Cross-user IDOR test skipped for '${tableName}' - probe row insertion failed: ${insertError.message}`,
          remediation: `Review table constraints or add real data for testing`
        });
        return;
      }
      
      probeRowInserted = true;
      
      // Get primary key for cleanup and tracking
      if (insertedRow && insertedRow.length > 0) {
        const idField = Object.keys(insertedRow[0]).find(k => k === 'id' || k.endsWith('_id'));
        if (idField) {
          probeRowId = { field: idField, value: insertedRow[0][idField] };
        }
      }
      
      if (verbose) {
        console.log(`  Probe row inserted: ${probeRowId ? `${probeRowId.field}=${probeRowId.value}` : 'no ID found'}`);
      }
    } else {
      // Table has existing data - get a row ID to test with
      if (existingRows && existingRows.length > 0) {
        const idField = Object.keys(existingRows[0]).find(k => k === 'id' || k.endsWith('_id'));
        if (idField) {
          probeRowId = { field: idField, value: existingRows[0][idField] };
        }
      }
      
      if (verbose && probeRowId) {
        console.log(`  Using existing row for test: ${probeRowId.field}=${probeRowId.value}`);
      }
    }
    
    // Step 3: Verify clientA can read it back
    if (probeRowId) {
      const { data: aData, error: aError } = await clientA
        .from(tableName)
        .select('*')
        .eq(probeRowId.field, probeRowId.value);
      
      if (verbose) {
        console.log(`  ClientA read test: ${aError ? `error - ${aError.message}` : `${aData ? aData.length : 0} rows`}`);
      }
      
      if (aError || !aData || aData.length === 0) {
        if (verbose) {
          console.log(`  Skipping: clientA cannot read the row (RLS may be blocking)`);
        }
        return;
      }
    }
    
    // Step 4: Try to read with clientB (the IDOR test)
    if (!probeRowId) {
      if (verbose) {
        console.log(`  Skipping: no primary key found for targeted query`);
      }
      
      findings.push({
        type: 'IDOR Test Skipped',
        severity: 'info',
        table: tableName,
        message: `Cross-user IDOR test skipped for '${tableName}' - no primary key found`,
        remediation: `Ensure table has an 'id' or '*_id' column for testing`
      });
      return;
    }
    
    if (verbose) {
      console.log(`  Testing cross-user read via clientB...`);
    }
    
    const { data: bData, error: bError } = await clientB
      .from(tableName)
      .select('*')
      .eq(probeRowId.field, probeRowId.value);
    
    if (verbose) {
      console.log(`  ClientB read test: ${bError ? `error - ${bError.message}` : `${bData ? bData.length : 0} rows`}`);
    }
    
    // If clientB got data back, we have an IDOR vulnerability
    if (!bError && bData && bData.length > 0) {
      findings.push({
        type: 'IDOR - Cross-User Read',
        severity: 'critical',
        table: tableName,
        probeId: `${probeRowId.field}=${probeRowId.value}`,
        evidence: {
          table: tableName,
          probeId: probeRowId.value,
          anonBReturnedRows: bData.length,
          sampleData: truncateForEvidence(bData[0])
        },
        message: `Table '${tableName}' allows cross-user data access - userB can read userA's data (${probeRowId.field}=${probeRowId.value})`,
        remediation: `Review RLS policies for '${tableName}'. Ensure policies restrict access using auth.uid() = user_id_column or similar user isolation checks.`
      });
      
      if (verbose) {
        console.log(`  ⚠️  CRITICAL: ClientB can read clientA's data - IDOR vulnerability detected`);
      }
    } else {
      if (verbose) {
        console.log(`  ✓ Cross-user read blocked - no IDOR vulnerability`);
      }
    }
    
  } catch (error) {
    if (verbose) {
      console.log(`  Error testing table: ${error.message}`);
    }
  } finally {
    // Step 5: Always cleanup probe row if inserted
    if (probeRowInserted && probeRowId) {
      if (verbose) {
        console.log(`  Cleaning up probe row...`);
      }
      
      try {
        const { error: deleteError } = await serviceClient
          .from(tableName)
          .delete()
          .eq(probeRowId.field, probeRowId.value);
        
        if (verbose) {
          if (deleteError) {
            console.log(`  Warning: Could not delete probe row: ${deleteError.message}`);
          } else {
            console.log(`  Probe row cleaned up`);
          }
        }
      } catch (cleanupError) {
        if (verbose) {
          console.log(`  Error during cleanup: ${cleanupError.message}`);
        }
      }
    }
  }
}

/**
 * Build a valid probe row by querying the table schema
 */
async function buildProbeRowData(serviceClient, tableName, verbose) {
  try {
    const { data: columns, error: schemaError } = await serviceClient
      .rpc('get_table_columns', { table_name_param: tableName });
    
    if (schemaError || !columns || columns.length === 0) {
      if (verbose) {
        console.log(`    Could not query table schema: ${schemaError ? schemaError.message : 'no columns'}`);
      }
      return null;
    }
    
    const probeData = {};
    
    for (const col of columns) {
      const columnName = col.column_name;
      const dataType = col.data_type;
      const isNullable = col.is_nullable === 'YES';
      const hasDefault = col.column_default !== null;
      
      // Skip columns with defaults or nullable
      if (isNullable || hasDefault) {
        continue;
      }
      
      // Generate safe value
      const value = generateSafeValue(dataType, columnName);
      
      if (value === undefined) {
        return null; // Can't handle this type
      }
      
      probeData[columnName] = value;
    }
    
    return probeData;
    
  } catch (error) {
    if (verbose) {
      console.log(`    Error building probe data: ${error.message}`);
    }
    return null;
  }
}

/**
 * Generate a safe throwaway value for a given SQL data type
 */
function generateSafeValue(dataType, columnName) {
  const type = dataType.toLowerCase();
  
  if (type.includes('char') || type.includes('text')) {
    return 'shrine_idor_probe';
  }
  
  if (type.includes('int') || type.includes('serial')) {
    return 0;
  }
  
  if (type.includes('numeric') || type.includes('decimal') || type.includes('real') || type.includes('double')) {
    return 0;
  }
  
  if (type.includes('bool')) {
    return false;
  }
  
  if (type.includes('timestamp') || type.includes('time') || type.includes('date')) {
    return new Date().toISOString();
  }
  
  if (type.includes('uuid')) {
    return '00000000-0000-4000-8000-000000000001';
  }
  
  if (type.includes('json')) {
    return {};
  }
  
  if (type.includes('array') || type.includes('[]')) {
    return [];
  }
  
  return undefined;
}

/**
 * Truncate evidence data to avoid exposing sensitive information
 */
function truncateForEvidence(rowData) {
  if (!rowData) return null;
  
  const truncated = {};
  const keys = Object.keys(rowData).slice(0, 5); // Only include first 5 fields
  
  for (const key of keys) {
    const value = rowData[key];
    if (typeof value === 'string' && value.length > 50) {
      truncated[key] = value.substring(0, 50) + '...';
    } else {
      truncated[key] = value;
    }
  }
  
  if (Object.keys(rowData).length > 5) {
    truncated['...'] = `${Object.keys(rowData).length - 5} more fields`;
  }
  
  return truncated;
}

module.exports = {
  testCrossUserIDOR
};
