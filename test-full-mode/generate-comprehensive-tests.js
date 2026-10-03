const fs = require('fs');
const path = require('path');

// Create a 100 MB file with real newlines and a secret planted across a chunk boundary
function createLargeFileWithNewlines() {
  console.log('Creating 100 MB file with newlines and chunk boundary secret...');
  
  const filePath = path.join(__dirname, 'large-file-100mb.log');
  const stream = fs.createWriteStream(filePath);
  
  const CHUNK_SIZE = 1024 * 1024; // 1MB - matches the streaming chunk size
  const TARGET_SIZE = 100 * 1024 * 1024; // 100MB
  
  // Create realistic log lines
  const logTemplates = [
    '[INFO] Application started successfully\n',
    '[DEBUG] Processing request from user_id={id}\n',
    '[WARN] Connection timeout, retrying...\n',
    '[ERROR] Failed to connect to database\n',
    '[INFO] User authenticated: {username}\n',
    '[DEBUG] Cache hit for key: {key}\n',
    '[INFO] Request completed in {time}ms\n',
  ];
  
  let bytesWritten = 0;
  let lineCount = 0;
  
  // Write until we're near the first chunk boundary
  while (bytesWritten < CHUNK_SIZE - 50) {
    const template = logTemplates[lineCount % logTemplates.length];
    const line = template
      .replace('{id}', Math.floor(Math.random() * 10000))
      .replace('{username}', `user${Math.floor(Math.random() * 1000)}`)
      .replace('{key}', `cache_${Math.floor(Math.random() * 10000)}`)
      .replace('{time}', Math.floor(Math.random() * 500));
    stream.write(line);
    bytesWritten += line.length;
    lineCount++;
  }
  
  // Plant a secret that spans the chunk boundary
  // Position it so "AKIA" starts before boundary and rest crosses over
  const beforeBoundary = 'config.aws_access_key=AK';
  const afterBoundary = 'IAIOSFODNN7REALSEC\n';
  const secret = beforeBoundary + afterBoundary;
  
  console.log(`Planting boundary secret at byte ${bytesWritten} (chunk boundary at ${CHUNK_SIZE})`);
  console.log(`Secret will span: "${beforeBoundary}" | boundary | "${afterBoundary}"`);
  stream.write(secret);
  bytesWritten += secret.length;
  lineCount++;
  
  // Continue writing log lines until we reach 100MB
  while (bytesWritten < TARGET_SIZE) {
    const template = logTemplates[lineCount % logTemplates.length];
    const line = template
      .replace('{id}', Math.floor(Math.random() * 10000))
      .replace('{username}', `user${Math.floor(Math.random() * 1000)}`)
      .replace('{key}', `cache_${Math.floor(Math.random() * 10000)}`)
      .replace('{time}', Math.floor(Math.random() * 500));
    stream.write(line);
    bytesWritten += line.length;
    lineCount++;
  }
  
  stream.end();
  
  return new Promise((resolve) => {
    stream.on('finish', () => {
      const stats = fs.statSync(filePath);
      console.log(`Created ${filePath}`);
      console.log(`  Size: ${(stats.size / (1024 * 1024)).toFixed(2)} MB`);
      console.log(`  Lines: ${lineCount}`);
      resolve();
    });
  });
}

// Create a 5MB minified bundle with embedded secrets
function createMinifiedBundle() {
  console.log('Creating 5 MB minified bundle...');
  
  const filePath = path.join(__dirname, 'app.bundle.min.js');
  const stream = fs.createWriteStream(filePath);
  
  const TARGET_SIZE = 5 * 1024 * 1024; // 5MB
  
  // Start with webpack boilerplate
  const header = '!function(e){var t={};function n(r){if(t[r])return t[r].exports;var o=t[r]={i:r,l:!1,exports:{}};return e[r].call(o.exports,o,o.exports,n),o.l=!0,o.exports}';
  stream.write(header);
  
  // Embed realistic secrets early in the bundle
  const secretsBlock = 'n.m=e,n.c=t,n.d=function(e,t,r){n.o(e,t)||Object.defineProperty(e,t,{enumerable:!0,get:r})},n.r=function(e){"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(e,"__esModule",{value:!0})};const config={stripeKey:"sk_live_51HqFxrKz9wXt2Pq8YhNmLpVbRcJdEfGhIjKl",openaiKey:"sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCdEf",githubToken:"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz123456",supabaseKey:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InRlc3QiLCJyb2xlIjoic2VydmljZV9yb2xlIiwiaWF0IjoxNjI1MDg1NjAwLCJleHAiOjE5NDA2NjE2MDB9.AAAAAAAAAAAABBBBBBBBBBBBCCCCCCCCCCCCDDDDDDDDDDDD"};';
  stream.write(secretsBlock);
  
  // Fill the rest with minified code patterns
  let bytesWritten = header.length + secretsBlock.length;
  
  const fillerPatterns = [
    'function a(e,t){return e+t}',
    'var b=function(e){return e.map(function(t){return t*2})};',
    'const c={x:1,y:2,z:function(){return this.x+this.y}};',
    'class D{constructor(e){this.value=e}getValue(){return this.value}}',
    'if(e&&t){console.log("success")}else{console.error("failed")}',
    'for(var i=0;i<100;i++){arr.push(i*i)}',
    'const result=await fetch(url).then(r=>r.json()).catch(e=>console.error(e));',
    'export default{name:"App",data(){return{count:0}},methods:{increment(){this.count++}}};',
  ];
  
  let patternIndex = 0;
  while (bytesWritten < TARGET_SIZE) {
    const pattern = fillerPatterns[patternIndex % fillerPatterns.length];
    stream.write(pattern);
    bytesWritten += pattern.length;
    patternIndex++;
  }
  
  stream.end();
  
  return new Promise((resolve) => {
    stream.on('finish', () => {
      const stats = fs.statSync(filePath);
      console.log(`Created ${filePath}`);
      console.log(`  Size: ${(stats.size / (1024 * 1024)).toFixed(2)} MB`);
      resolve();
    });
  });
}

// Create a .gitignore file
function createGitignore() {
  console.log('Creating .gitignore...');
  
  const gitignorePath = path.join(__dirname, '.gitignore');
  const content = `node_modules
*.log
temp-*
secret.env
`;
  
  fs.writeFileSync(gitignorePath, content);
  console.log('Created .gitignore');
}

// Create a gitignored file with secrets (should be found by default, skipped with --respect-gitignore)
function createGitignoredFile() {
  console.log('Creating gitignored file with secrets...');
  
  const filePath = path.join(__dirname, 'secret.env');
  const content = `# This file is in .gitignore but should be scanned by default
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7GITIGNOR
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYgitignored123
STRIPE_SECRET_KEY=sk_live_51AbCdEfGhIjKlMnOpQrStUvWxYz123456
DATABASE_URL=postgresql://admin:SuperSecret456@db.example.com:5432/proddb
`;
  
  fs.writeFileSync(filePath, content);
  console.log('Created secret.env (gitignored)');
}

// Create a normal config file with secrets
function createConfigFile() {
  console.log('Creating normal config file...');
  
  const filePath = path.join(__dirname, 'config.js');
  const content = `// Application configuration
module.exports = {
  stripe: {
    publicKey: 'pk_test_51HqFxrKz9wXt2Pq8notasecret',
    secretKey: 'sk_live_51HqFxrKz9wXt2Pq8RealSecret123456789'
  },
  github: {
    token: 'ghp_RealGitHubPersonalAccessToken123456'
  },
  openai: {
    apiKey: 'sk-proj-RealOpenAIProjectKey1234567890AbCdEf'
  }
};
`;
  
  fs.writeFileSync(filePath, content);
  console.log('Created config.js');
}

// Main execution
async function main() {
  console.log('=== Generating Comprehensive Test Files ===\n');
  
  const startTime = Date.now();
  
  createGitignore();
  createGitignoredFile();
  createConfigFile();
  await createMinifiedBundle();
  await createLargeFileWithNewlines();
  
  const endTime = Date.now();
  const duration = ((endTime - startTime) / 1000).toFixed(2);
  
  console.log(`\n=== Test files created in ${duration}s ===`);
  console.log('\nTest scenarios:');
  console.log('  1. 100MB file with real newlines and chunk boundary secret');
  console.log('  2. 5MB minified bundle with embedded secrets');
  console.log('  3. Gitignored file (secret.env) with secrets - SHOULD BE FOUND by default');
  console.log('  4. Normal config.js with secrets');
  console.log('\nTo test:');
  console.log('  cd temp-test');
  console.log('  node node_modules/shrine/bin/shrine.js scan --path ../test-full-mode --verbose --skip-auth');
  console.log('  node node_modules/shrine/bin/shrine.js scan --path ../test-full-mode --respect-gitignore --verbose --skip-auth');
}

main().catch(console.error);
