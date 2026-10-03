const { saveAccessKey, validateAccessKey, clearAccessKey, getBackendUrl, getBackendAnonKey, requireAuth, SIGNUP_PAGE_URL } = require('../auth/config');

async function loginCommand(accessKey, options) {
  // Supabase backend credentials (defaults are built-in, can be overridden via env vars or options)
  const supabaseUrl = options.backendUrl || process.env.SHRINE_BACKEND_URL || getBackendUrl();
  const supabaseAnonKey = options.backendAnonKey || process.env.SHRINE_BACKEND_ANON_KEY || getBackendAnonKey();
  
  if (!accessKey) {
    console.error('\n❌ Please provide an access key.');
    console.error('Usage: shrine login <access-key>');
    console.error(`\nGet your access key at: ${SIGNUP_PAGE_URL}\n`);
    process.exitCode = 1;
    return;
  }
  
  // Validate the format
  if (!accessKey.startsWith('shrine_')) {
    console.error('\n❌ Invalid access key format. Keys should start with "shrine_"');
    process.exitCode = 1;
    return;
  }
  
  console.log('Validating access key...');
  
  // Validate against Supabase backend
  const validation = await validateAccessKey(accessKey, supabaseUrl, supabaseAnonKey);
  
  if (!validation.valid) {
    console.error(`\n❌ Invalid access key: ${validation.error}`);
    console.error('Please check your key and try again.');
    console.error(`Get a new key at: ${SIGNUP_PAGE_URL}\n`);
    process.exitCode = 1;
    return;
  }
  
  // Save the key locally
  const saved = saveAccessKey(accessKey);
  
  if (!saved) {
    console.error('\n❌ Failed to save access key locally.');
    process.exitCode = 1;
    return;
  }
  
  console.log('\n✓ Access key validated and saved successfully!');
  if (validation.tier) {
    console.log(`  Tier: ${validation.tier}`);
  }
  
  console.log('\nYou can now use Shrine CLI commands.\n');
}

async function logoutCommand() {
  const cleared = clearAccessKey();
  
  if (cleared) {
    console.log('\n✓ Logged out successfully. Access key removed.\n');
  } else {
    console.error('\n❌ Failed to remove access key.\n');
    process.exitCode = 1;
    return;
  }
}

module.exports = { loginCommand, logoutCommand };
