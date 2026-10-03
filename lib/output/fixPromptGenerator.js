const chalk = require('chalk');

/**
 * Generate fix prompts for findings (batched by type and severity)
 */
function generateFixPrompts(findings, options = {}) {
  // Group findings by type + severity
  const groups = {};
  
  for (const finding of findings) {
    const severity = finding.confidence === 'high' ? 'high' : 'medium';
    const key = `${finding.type}::${severity}`;
    
    if (!groups[key]) {
      groups[key] = {
        type: finding.type,
        severity: severity,
        locations: []
      };
    }
    
    groups[key].locations.push({
      file: finding.file,
      line: finding.line
    });
  }
  
  // Generate one prompt per group
  const prompts = [];
  for (const group of Object.values(groups)) {
    const prompt = generateBatchedFixPrompt(group);
    if (prompt) {
      prompts.push(prompt);
    }
  }
  
  return prompts;
}

/**
 * Generate a batched fix prompt for a group of findings
 */
function generateBatchedFixPrompt(group) {
  const { type, severity, locations } = group;
  
  // Generate "why this matters" based on type
  const whyMatters = getWhyMatters(type);
  
  // Generate specific fix instruction for the type
  const fixInstruction = getBatchedFixInstruction(type, locations);
  
  // Generate verification steps
  const verificationSteps = getVerificationSteps(type, group);
  
  // Add security strictness for high severity
  const securityNote = severity === 'high' 
    ? '\n\nIMPORTANT: Do not weaken existing auth/security elsewhere in this fix.'
    : '';
  
  // Format locations list
  const locationsList = locations.map(loc => `  - ${loc.file}:${loc.line}`).join('\n');
  
  return {
    type,
    severity,
    count: locations.length,
    locations,
    whyMatters,
    fixInstruction,
    fullPrompt: `Type: ${type}
Severity: ${severity}
Occurrences: ${locations.length}

Locations:
${locationsList}

Why this matters: ${whyMatters}

Fix instruction: ${fixInstruction}${securityNote}

Verify the fix:
${verificationSteps}`
  };
}

/**
 * Get "why this matters" explanation for each vulnerability type
 */
function getWhyMatters(type) {
  const explanations = {
    'AWS Access Key ID': 'Exposed AWS credentials allow attackers to access your cloud resources and incur charges.',
    'AWS Secret Access Key': 'This secret grants full access to AWS services and can lead to data breaches or resource hijacking.',
    'Stripe Live Secret Key': 'Attackers can process unauthorized payments, refunds, or access customer payment data.',
    'Stripe Test Secret Key': 'While limited to test mode, this exposes your Stripe integration patterns and test data.',
    'Stripe Live Restricted Key': 'Limited Stripe access is still exploitable for specific operations like reading customer data.',
    'Stripe Test Restricted Key': 'Test keys expose your payment integration logic and development practices.',
    'OpenAI API Key': 'Unauthorized API usage can drain your credits and expose conversational data.',
    'OpenAI Project API Key': 'Project-specific keys can access associated resources and incur costs.',
    'Anthropic API Key': 'Exposed API keys lead to unauthorized usage and potential data exposure.',
    'GitHub Personal Access Token': 'Attackers can read/write repositories, access private code, and modify settings.',
    'GitHub Fine-grained PAT': 'Even scoped tokens can expose specific repositories or user data.',
    'Google API Key': 'Unrestricted API keys can access Google Cloud services and exhaust quotas.',
    'Twilio Account SID': 'Combined with auth token, this allows sending messages and accessing call logs.',
    'Twilio Auth Token': 'Full access to send SMS, make calls, and view account activity.',
    'Database Connection String': 'Direct database access allows data theft, modification, or deletion.',
    'Supabase Service Role Key': 'Bypasses Row Level Security and grants full database access.',
    'Supabase Anon Key': 'While limited by RLS, can be used to probe your database structure and policies.',
    'JWT Token': 'Valid tokens allow session hijacking and unauthorized access to user accounts.',
    'Generic API Key': 'Unidentified keys may grant access to third-party services or internal systems.',
    'Committed .env value': 'Environment variables in git history remain accessible even after removal.',
    'Private Key': 'Private keys enable impersonation, decryption of data, or unauthorized access.',
    'SSH Private Key': 'Full server access and ability to authenticate as the key owner.',
    'RSA Private Key': 'Enables decryption of encrypted data and signing of arbitrary content.',
    'Default': 'Exposed credentials can be exploited to gain unauthorized access or cause security breaches.'
  };
  
  return explanations[type] || explanations['Default'];
}

/**
 * Get specific fix instruction for each vulnerability type
 */
function getFixInstruction(type, finding) {
  const file = finding.file;
  const line = finding.line;
  
  // Check if it's a .env file
  if (file.includes('.env')) {
    return `In ${file}, the secret on line ${line} is committed to version control. Move this value to a .env file (add .env to .gitignore), load it via environment variables, and rotate the exposed credential immediately. Remove the secret from git history using git filter-branch or BFG Repo-Cleaner.`;
  }
  
  // Type-specific instructions
  const instructions = {
    'AWS Access Key ID': `In ${file} at line ${line}, replace the hardcoded AWS Access Key ID with an environment variable (e.g., process.env.AWS_ACCESS_KEY_ID). Use AWS IAM to rotate the exposed key immediately.`,
    'AWS Secret Access Key': `In ${file} at line ${line}, replace the hardcoded AWS Secret Access Key with an environment variable (e.g., process.env.AWS_SECRET_ACCESS_KEY). Rotate the key in AWS IAM immediately and audit CloudTrail logs for unauthorized access.`,
    'Stripe Live Secret Key': `In ${file} at line ${line}, replace the hardcoded Stripe secret key with process.env.STRIPE_SECRET_KEY. Roll the key in your Stripe Dashboard immediately and check recent webhook/payment activity for unauthorized transactions.`,
    'Stripe Test Secret Key': `In ${file} at line ${line}, replace the hardcoded test key with process.env.STRIPE_TEST_SECRET_KEY. While this is a test key, it still exposes your integration patterns—rotate it as a security best practice.`,
    'Stripe Live Restricted Key': `In ${file} at line ${line}, replace the restricted key with process.env.STRIPE_RESTRICTED_KEY and rotate it immediately in Stripe Dashboard.`,
    'Stripe Test Restricted Key': `In ${file} at line ${line}, move the test restricted key to environment variables (process.env.STRIPE_TEST_RESTRICTED_KEY).`,
    'OpenAI API Key': `In ${file} at line ${line}, replace the hardcoded OpenAI API key with process.env.OPENAI_API_KEY. Rotate the key at platform.openai.com/api-keys and review recent usage for anomalies.`,
    'OpenAI Project API Key': `In ${file} at line ${line}, move the project API key to process.env.OPENAI_PROJECT_KEY and rotate it in your OpenAI project settings.`,
    'Anthropic API Key': `In ${file} at line ${line}, replace the hardcoded Anthropic API key with process.env.ANTHROPIC_API_KEY and rotate it immediately in your Anthropic console.`,
    'GitHub Personal Access Token': `In ${file} at line ${line}, replace the hardcoded GitHub PAT with process.env.GITHUB_TOKEN. Revoke the token at github.com/settings/tokens and generate a new one. Review repository access logs for unauthorized activity.`,
    'GitHub Fine-grained PAT': `In ${file} at line ${line}, move the fine-grained PAT to process.env.GITHUB_TOKEN and revoke/regenerate it at github.com/settings/tokens.`,
    'Google API Key': `In ${file} at line ${line}, replace the hardcoded Google API key with process.env.GOOGLE_API_KEY. Rotate the key in Google Cloud Console and restrict it by IP/referrer if possible.`,
    'Twilio Account SID': `In ${file} at line ${line}, replace the hardcoded Twilio Account SID with process.env.TWILIO_ACCOUNT_SID. While the SID alone is less sensitive, it should still be treated as confidential configuration.`,
    'Twilio Auth Token': `In ${file} at line ${line}, replace the hardcoded Twilio Auth Token with process.env.TWILIO_AUTH_TOKEN. Rotate the token immediately at twilio.com/console and check recent SMS/call logs for abuse.`,
    'Database Connection String': `In ${file} at line ${line}, replace the hardcoded connection string with process.env.DATABASE_URL. Rotate database credentials immediately and audit connection logs for unauthorized access.`,
    'Supabase Service Role Key': `In ${file} at line ${line}, replace the hardcoded service role key with process.env.SUPABASE_SERVICE_ROLE_KEY. This key bypasses Row Level Security—ensure it's only used in trusted server environments. If exposed, contact Supabase support to rotate.`,
    'Supabase Anon Key': `In ${file} at line ${line}, replace the hardcoded anon key with process.env.SUPABASE_ANON_KEY. While protected by RLS, rotate it via Supabase project settings to prevent API abuse.`,
    'JWT Token': `In ${file} at line ${line}, remove the hardcoded JWT token. JWTs should never be committed—they're session-specific. If this is test data, use a mock/invalid token. If real, invalidate the session and audit access logs.`,
    'Generic API Key': `In ${file} at line ${line}, replace the hardcoded API key with an appropriate environment variable (e.g., process.env.API_KEY). Identify the service and rotate the key immediately.`,
    'Committed .env value': `The value on line ${line} of ${file} is committed to git history and remains accessible. Remove this file from version control, add .env to .gitignore, and use git filter-branch or BFG Repo-Cleaner to purge it from history. Rotate all exposed secrets.`,
    'Private Key': `In ${file} at line ${line}, remove the hardcoded private key. Store it securely outside version control (e.g., in a secrets manager or encrypted keystore). Revoke the key and generate a new one immediately.`,
    'SSH Private Key': `In ${file} at line ${line}, remove the SSH private key from the codebase. Remove it from git history, revoke it on all servers (~/.ssh/authorized_keys), and generate a new keypair.`,
    'RSA Private Key': `In ${file} at line ${line}, remove the RSA private key. Store it in a secure secrets manager, revoke it from all systems, and generate a new keypair immediately.`,
    'Default': `In ${file} at line ${line}, replace the hardcoded secret with an environment variable. Load it securely at runtime and rotate the exposed credential immediately.`
  };
  
  return instructions[type] || instructions['Default'];
}

/**
 * Get verification steps for each vulnerability type
 */
function getVerificationSteps(type, group) {
  const { locations } = group;
  
  // RLS finding types
  if (type === 'RLS Disabled' || type === 'No RLS Policies') {
    const table = group.table || 'the_table';
    return `1. Verify RLS is enabled: SELECT tablename, rowsecurity FROM pg_tables WHERE tablename = '${table}';
2. Test as anonymous user (expect denied): Use anon key to query ${table}
3. Test as user A (expect denied unless explicitly allowed): Create test user A, attempt to read/write
4. Test as user B (expect denied from seeing A's data): Create test user B, verify isolation from user A's rows`;
  }
  
  if (type === 'Permissive RLS Policy') {
    const table = group.table || 'the_table';
    const policy = group.policy || 'the_policy';
    return `1. Review the policy: SELECT * FROM pg_policies WHERE tablename = '${table}' AND policyname = '${policy}';
2. Test as anonymous user (expect denied): Use anon key to query ${table}
3. Test as user A (expect restricted access): Create test user A, verify they only see their own data
4. Test as user B (expect denied from seeing A's data): Create test user B, attempt to read user A's rows`;
  }
  
  if (type === 'RLS Bypass - Anon Read') {
    const table = group.table || 'the_table';
    return `1. Test as anonymous user (expect denied): const { data, error } = await anonClient.from('${table}').select()
2. Verify the error is permission-related, not successful read
3. Test as user A (expect allowed only for their data): Create authenticated user A, verify restricted access
4. Test as user B (expect denied from seeing A's data): Create user B, verify isolation`;
  }
  
  if (type === 'RLS Bypass - Anon Write') {
    const table = group.table || 'the_table';
    return `1. Test as anonymous user (expect denied): const { error } = await anonClient.from('${table}').insert({ test: 'data' })
2. Verify the error is permission-related, not successful write
3. Test as user A (expect allowed only for their data): Create authenticated user A, verify restricted write access
4. Test as user B (expect denied from modifying A's data): Create user B, attempt to update user A's rows`;
  }
  
  if (type === 'Public Storage Bucket') {
    const bucket = group.bucket || 'the_bucket';
    return `1. Verify bucket policy in Supabase dashboard: Check storage settings for '${bucket}'
2. Test as anonymous user (expect denied): Attempt to list/download files without authentication
3. Test as user A (expect restricted access): Create authenticated user A, verify they only access their own files
4. Test as user B (expect denied from accessing A's files): Create user B, attempt to access user A's files`;
  }
  
  if (type === 'SECURITY DEFINER Function') {
    const func = group.function || 'the_function';
    return `1. Review the function definition: SELECT * FROM pg_proc WHERE proname = '${func}';
2. Test as anonymous user (expect denied or safe behavior): Call function with anon key
3. Test as user A (expect controlled access): Verify function doesn't expose other users' data
4. Test as user B (expect isolation): Ensure function maintains data isolation between users`;
  }
  
  // Secret finding types - generic verification
  const file = locations[0].file;
  return `1. Verify the secret is loaded from environment variables, not hardcoded in ${file}
2. Test that the application still functions correctly with the environment variable
3. Confirm the exposed credential has been rotated/revoked at the service provider
4. If committed to git history, verify removal: git log --all --full-history -- "${file}"`;
}

/**
 * Get batched fix instruction for multiple locations of the same vulnerability type
 */
function getBatchedFixInstruction(type, locations) {
  // Check if any location is a .env file
  const hasEnvFile = locations.some(loc => loc.file.includes('.env'));
  
  // Type-specific batched instructions
  const instructions = {
    'AWS Access Key ID': `Replace all hardcoded AWS Access Key IDs with environment variables (e.g., process.env.AWS_ACCESS_KEY_ID). Use AWS IAM to rotate the exposed keys immediately.`,
    'AWS Secret Access Key': `Replace all hardcoded AWS Secret Access Keys with environment variables (e.g., process.env.AWS_SECRET_ACCESS_KEY). Rotate all keys in AWS IAM immediately and audit CloudTrail logs for unauthorized access.`,
    'Stripe Live Secret Key': `Replace all hardcoded Stripe secret keys with process.env.STRIPE_SECRET_KEY. Roll the keys in your Stripe Dashboard immediately and check recent webhook/payment activity for unauthorized transactions.`,
    'Stripe Test Secret Key': `Replace all hardcoded test keys with process.env.STRIPE_TEST_SECRET_KEY. While these are test keys, they still expose your integration patterns—rotate them as a security best practice.`,
    'Stripe Live Restricted Key': `Replace all restricted keys with process.env.STRIPE_RESTRICTED_KEY and rotate them immediately in Stripe Dashboard.`,
    'Stripe Test Restricted Key': `Move all test restricted keys to environment variables (process.env.STRIPE_TEST_RESTRICTED_KEY).`,
    'OpenAI API Key': `Replace all hardcoded OpenAI API keys with process.env.OPENAI_API_KEY. Rotate the keys at platform.openai.com/api-keys and review recent usage for anomalies.`,
    'OpenAI Project API Key': `Move all project API keys to process.env.OPENAI_PROJECT_KEY and rotate them in your OpenAI project settings.`,
    'Anthropic API Key': `Replace all hardcoded Anthropic API keys with process.env.ANTHROPIC_API_KEY and rotate them immediately in your Anthropic console.`,
    'GitHub Personal Access Token': `Replace all hardcoded GitHub PATs with process.env.GITHUB_TOKEN. Revoke all tokens at github.com/settings/tokens and generate new ones. Review repository access logs for unauthorized activity.`,
    'GitHub Fine-grained PAT': `Move all fine-grained PATs to process.env.GITHUB_TOKEN and revoke/regenerate them at github.com/settings/tokens.`,
    'Google API Key': `Replace all hardcoded Google API keys with process.env.GOOGLE_API_KEY. Rotate the keys in Google Cloud Console and restrict them by IP/referrer if possible.`,
    'Twilio Account SID': `Replace all hardcoded Twilio Account SIDs with process.env.TWILIO_ACCOUNT_SID. While the SID alone is less sensitive, it should still be treated as confidential configuration.`,
    'Twilio Auth Token': `Replace all hardcoded Twilio Auth Tokens with process.env.TWILIO_AUTH_TOKEN. Rotate all tokens immediately at twilio.com/console and check recent SMS/call logs for abuse.`,
    'Database Connection String': `Replace all hardcoded connection strings with process.env.DATABASE_URL. Rotate database credentials immediately and audit connection logs for unauthorized access.`,
    'Supabase Service Role Key': `Replace all hardcoded service role keys with process.env.SUPABASE_SERVICE_ROLE_KEY. This key bypasses Row Level Security—ensure it's only used in trusted server environments. If exposed, contact Supabase support to rotate.`,
    'Supabase Anon Key': `Replace all hardcoded anon keys with process.env.SUPABASE_ANON_KEY. While protected by RLS, rotate it via Supabase project settings to prevent API abuse.`,
    'JWT Token': `Remove all hardcoded JWT tokens. JWTs should never be committed—they're session-specific. If these are test data, use mock/invalid tokens. If real, invalidate the sessions and audit access logs.`,
    'Generic API Key': `Replace all hardcoded API keys with appropriate environment variables (e.g., process.env.API_KEY). Identify the services and rotate the keys immediately.`,
    'Committed .env value': `These values are committed to git history and remain accessible even after removal. Remove these files from version control, add .env to .gitignore, and use git filter-branch or BFG Repo-Cleaner to purge them from history. Rotate all exposed secrets.`,
    'Private Key': `Remove all hardcoded private keys. Store them securely outside version control (e.g., in a secrets manager or encrypted keystore). Revoke all keys and generate new ones immediately.`,
    'SSH Private Key': `Remove all SSH private keys from the codebase. Remove them from git history, revoke them on all servers (~/.ssh/authorized_keys), and generate new keypairs.`,
    'RSA Private Key': `Remove all RSA private keys. Store them in a secure secrets manager, revoke them from all systems, and generate new keypairs immediately.`,
    'Default': `Replace all hardcoded secrets with environment variables. Load them securely at runtime and rotate all exposed credentials immediately.`
  };
  
  // Use .env-specific instruction if applicable
  if (hasEnvFile && type === 'Committed .env value') {
    return instructions['Committed .env value'];
  }
  
  return instructions[type] || instructions['Default'];
}

/**
 * Format and display fix prompts
 */
function displayFixPrompts(prompts) {
  if (prompts.length === 0) {
    return;
  }
  
  console.log('\n' + chalk.bold.blue('=== Fix Prompts ===\n'));
  console.log(chalk.gray('Copy these prompts to your AI assistant for guided remediation.\n'));
  
  for (let i = 0; i < prompts.length; i++) {
    const prompt = prompts[i];
    const color = prompt.severity === 'high' ? chalk.red : chalk.yellow;
    
    console.log(color.bold(`[${i + 1}/${prompts.length}] ${prompt.type}`));
    console.log(chalk.gray('─'.repeat(80)));
    console.log(prompt.fullPrompt);
    console.log('');
  }
}

module.exports = {
  generateFixPrompts,
  displayFixPrompts
};
