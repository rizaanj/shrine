const fs = require('fs');
const path = require('path');
const os = require('os');
const { createClient } = require('@supabase/supabase-js');

// Configuration constants
const SIGNUP_PAGE_URL = 'https://shrinecli.netlify.app/';

// Shrine backend credentials (can be overridden via environment variables)
// Note: The anon key is safe to ship publicly - it's the public Supabase anon key
// with access controlled by RLS policies, not a service role or secret key
const DEFAULT_BACKEND_URL = 'https://andboqwyotgmdekrvbof.supabase.co';
const DEFAULT_BACKEND_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFuZGJvcXd5b3RnbWRla3J2Ym9mIiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTA1MzUwNzIsImV4cCI6MjEwNjExMTA3Mn0.g1ip5lmXHgEyOR-3CxJBKUq4kXgYFARz0YXj-GVMyXc';

// Get backend URL (env var override or default)
function getBackendUrl() {
  return process.env.SHRINE_BACKEND_URL || DEFAULT_BACKEND_URL;
}

// Get backend anon key (env var override or default)
function getBackendAnonKey() {
  return process.env.SHRINE_BACKEND_ANON_KEY || DEFAULT_BACKEND_ANON_KEY;
}

// Configuration directory path
function getConfigDir() {
  const homeDir = os.homedir();
  const configDir = path.join(homeDir, '.shrine');
  
  // Create directory if it doesn't exist
  if (!fs.existsSync(configDir)) {
    fs.mkdirSync(configDir, { recursive: true });
  }
  
  return configDir;
}

function getConfigPath() {
  return path.join(getConfigDir(), 'config.json');
}

// Read config file
function readConfig() {
  const configPath = getConfigPath();
  
  if (!fs.existsSync(configPath)) {
    return {};
  }
  
  try {
    const data = fs.readFileSync(configPath, 'utf-8');
    return JSON.parse(data);
  } catch (error) {
    console.error(`Error reading config: ${error.message}`);
    return {};
  }
}

// Write config file
function writeConfig(config) {
  const configPath = getConfigPath();
  
  try {
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2), 'utf-8');
    return true;
  } catch (error) {
    console.error(`Error writing config: ${error.message}`);
    return false;
  }
}

// Get saved access key
function getAccessKey() {
  const config = readConfig();
  return config.accessKey || null;
}

// Save access key
function saveAccessKey(accessKey) {
  const config = readConfig();
  config.accessKey = accessKey;
  config.lastLogin = new Date().toISOString();
  return writeConfig(config);
}

// Clear access key
function clearAccessKey() {
  const config = readConfig();
  delete config.accessKey;
  delete config.lastLogin;
  return writeConfig(config);
}

// Validate access key against Supabase
async function validateAccessKey(accessKey, supabaseUrl, supabaseAnonKey) {
  if (!accessKey) {
    return { valid: false, error: 'No access key provided' };
  }
  
  // Dev mode bypass - only if explicitly enabled via environment variable
  if (process.env.SHRINE_DEV_SKIP_VALIDATION === '1') {
    console.warn('⚠️  Warning: Validation skipped (SHRINE_DEV_SKIP_VALIDATION=1)');
    return { valid: true, skipValidation: true };
  }
  
  // Use provided credentials or fall back to defaults
  const backendUrl = supabaseUrl || getBackendUrl();
  const backendAnonKey = supabaseAnonKey || getBackendAnonKey();
  
  try {
    const supabase = createClient(backendUrl, backendAnonKey);
    
    // Call the validate_access_key RPC function
    const { data, error } = await supabase
      .rpc('validate_access_key', { key: accessKey });
    
    if (error) {
      return { valid: false, error: error.message };
    }
    
    // RPC returns an array of rows, get the first one
    const result = Array.isArray(data) && data.length > 0 ? data[0] : null;
    
    if (!result) {
      return { valid: false, error: 'Invalid or inactive access key' };
    }
    
    if (!result.is_active) {
      return { valid: false, error: 'Access key has been deactivated' };
    }
    
    return { 
      valid: true, 
      tier: result.tier 
    };
  } catch (error) {
    return { valid: false, error: error.message };
  }
}

// Check if user is authenticated (has valid access key)
async function requireAuth(supabaseUrl, supabaseAnonKey) {
  const accessKey = getAccessKey();
  
  if (!accessKey) {
    console.error('\n❌ No access key found.');
    console.error(`Get your access key at: ${SIGNUP_PAGE_URL}`);
    console.error('Then run: shrine login <your-access-key>\n');
    process.exitCode = 1;
    return;
  }
  
  // Use provided credentials or fall back to defaults
  const backendUrl = supabaseUrl || getBackendUrl();
  const backendAnonKey = supabaseAnonKey || getBackendAnonKey();
  
  // Validate the key
  const validation = await validateAccessKey(accessKey, backendUrl, backendAnonKey);
  
  if (!validation.valid) {
    // Check if it's a network error (allow command to proceed)
    const isNetworkError = validation.error && (
      validation.error.includes('fetch') ||
      validation.error.includes('network') ||
      validation.error.includes('ENOTFOUND') ||
      validation.error.includes('ECONNREFUSED') ||
      validation.error.includes('ETIMEDOUT') ||
      validation.error.toLowerCase().includes('failed to fetch')
    );
    
    if (isNetworkError) {
      console.warn('⚠️  Warning: Cannot reach validation server, proceeding offline');
      return { authenticated: true, offline: true };
    }
    
    // Invalid or inactive key - delete it and exit
    clearAccessKey();
    console.error('\n❌ Access revoked');
    console.error(`Get a new access key at: ${SIGNUP_PAGE_URL}\n`);
    process.exitCode = 1;
    return;
  }
  
  if (validation.skipValidation) {
    // Dev mode - no validation
    return { authenticated: true, devMode: true };
  }
  
  return {
    authenticated: true,
    userId: validation.userId,
    tier: validation.tier
  };
}

module.exports = {
  getConfigDir,
  getConfigPath,
  getAccessKey,
  saveAccessKey,
  clearAccessKey,
  validateAccessKey,
  requireAuth,
  getBackendUrl,
  getBackendAnonKey,
  SIGNUP_PAGE_URL
};
