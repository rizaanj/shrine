// Test script to verify anon user cannot directly access beta_access table
const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL = 'https://andboqwyotgmdekrvbof.supabase.co';
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFuZGJvcXd5b3RnbWRla3J2Ym9mIiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTA1MzUwNzIsImV4cCI6MjEwNjExMTA3Mn0.g1ip5lmXHgEyOR-3CxJBKUq4kXgYFARz0YXj-GVMyXc';

async function test() {
  const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
  
  console.log('Testing direct SELECT on beta_access table (should fail)...');
  const { data: selectData, error: selectError } = await supabase
    .from('beta_access')
    .select('*')
    .limit(1);
  
  if (selectError) {
    console.log('✓ Direct SELECT blocked (as expected):', selectError.message);
  } else {
    console.log('✗ Direct SELECT succeeded (NOT expected):', selectData);
  }
  
  console.log('\nTesting RPC validate_access_key with valid key...');
  const { data: rpcData, error: rpcError } = await supabase
    .rpc('validate_access_key', { key: 'shrine_mfkxasbgx689zh8c' });
  
  if (rpcError) {
    console.log('✗ RPC call failed:', rpcError.message);
  } else {
    console.log('✓ RPC call succeeded:', rpcData);
  }
  
  console.log('\nTesting RPC validate_access_key with invalid key...');
  const { data: rpcInvalidData, error: rpcInvalidError } = await supabase
    .rpc('validate_access_key', { key: 'shrine_invalid123456' });
  
  if (rpcInvalidError) {
    console.log('✗ RPC call failed:', rpcInvalidError.message);
  } else {
    console.log('✓ RPC call succeeded (empty result expected):', rpcInvalidData);
  }
}

test().catch(console.error);
