const jwt = require('jsonwebtoken');
const path = require('path');
const { scanDirectory } = require('../scanner/fileWalker');

function redactSecret(secret) {
  if (secret.length <= 8) {
    return '****';
  }
  const start = secret.substring(0, 4);
  const end = secret.substring(secret.length - 4);
  const middle = '*'.repeat(Math.min(secret.length - 8, 20));
  return `${start}${middle}${end}`;
}

/**
 * Scan for JWT tokens and analyze their security
 */
async function scanJWT(options = {}) {
  const findings = [];
  const verbose = options.verbose || false;
  const includeTests = options.includeTests || false;
  
  if (verbose) {
    console.log('\nScanning for JWT tokens...');
  }
  
  try {
    // Scan for files that might contain JWTs
    const scanRoot = path.resolve(options.path || process.cwd());
    const files = await scanDirectory(scanRoot, verbose);
    
    // Filter to relevant file types (JS, TS, JSON, config files)
    const relevantFiles = files.filter(file => {
      const ext = path.extname(file).toLowerCase();
      return ['.js', '.ts', '.jsx', '.tsx', '.json', '.env', '.config.js', '.config.ts'].includes(ext);
    });
    
    if (verbose) {
      console.log(`Scanning ${relevantFiles.length} files for JWT tokens`);
    }
    
    // Scan each file for JWT tokens
    for (const file of relevantFiles) {
      const relativePath = path.relative(scanRoot, file);
      const fileFindings = await scanFileForJWT(file, relativePath, options);
      findings.push(...fileFindings);
    }
    
  } catch (error) {
    if (verbose) {
      console.error(`Error during JWT scan: ${error.message}`);
    }
    // Don't fail the entire scan for JWT checker issues
  }
  
  return findings;
}

/**
 * Scan a single file for JWT tokens and analyze them
 */
async function scanFileForJWT(filePath, relativePath, options) {
  const findings = [];
  const verbose = options.verbose || false;
  const includeTests = options.includeTests || false;
  
  try {
    // Skip test files if not included
    if (!includeTests && isTestFile(filePath)) {
      return findings;
    }
    
    const content = await require('fs').promises.readFile(filePath, 'utf8');
    const lines = content.split('\n');
    
    // JWT regex pattern - updated to allow empty signature (for 'none' algorithm)
    // Format: header.payload.signature (signature can be empty for none algorithm)
    const jwtPattern = /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]*/g;
    
    // Find all JWT matches in the file
    let match;
    while ((match = jwtPattern.exec(content)) !== null) {
      const token = match[0];
      const lineNumber = getLineNumberFromOffset(content, match.index);
      
      // Skip if it looks like a placeholder/test value
      if (isPlaceholderJWT(token, lines[lineNumber - 1])) {
        if (verbose) {
          console.log(`Skipping placeholder JWT at ${relativePath}:${lineNumber}`);
        }
        continue;
      }

      // Analyze the JWT
      const tokenFindings = analyzeJWT(token, relativePath, lineNumber, content, lines);
      findings.push(...tokenFindings);
    }
    
  } catch (error) {
    if (verbose) {
      console.error(`Error scanning file ${filePath}: ${error.message}`);
    }
  }
  
  return findings;
}

/**
 * Check if a file path indicates a test file
 */
function isTestFile(filePath) {
  const testPatterns = [
    '/__tests__/', '/__mocks__/', '/test-fixtures/', '/fixtures/', 
    '/tests/', '/spec/', '/e2e/', '.test.', '.spec.'
  ];
  return testPatterns.some(pattern => filePath.includes(pattern));
}

/**
 * Get line number from character offset in a string
 */
function getLineNumberFromOffset(str, offset) {
  return str.slice(0, offset).split('\n').length;
}

/**
 * Check if a JWT looks like a placeholder/test value
 */
function isPlaceholderJWT(token, line) {
  if (!line) return false;
  
  const lowerLine = line.toLowerCase();
  const placeholderPatterns = [
    'example', 'placeholder', 'dummy', 'fake', 'test', 
    'your-token-here', 'sample', 'xxx', 'yyy', 'zzz',
    'jwt-token', 'test-token', 'placeholder-token'
  ];
  
  return placeholderPatterns.some(pattern => lowerLine.includes(pattern));
}

/**
 * Analyze a JWT token for security issues
 */
function analyzeJWT(token, filePath, lineNumber, fullContent, lines) {
  const findings = [];
  
  try {
    // Decode JWT without verifying signature
    const decoded = jwt.decode(token, { complete: true });
    
    if (!decoded) {
      // Not a valid JWT
      return findings;
    }
    
    const header = decoded.header;
    const payload = decoded.payload;
    
    // Get the line content for context
    const lineContent = lines[lineNumber - 1] || '';
    
  // Check 1: Algorithm is 'none'
  if (header.alg === 'none') {
    findings.push({
      type: 'JWT None Algorithm',
      confidence: 'high',
      file: filePath,
      line: lineNumber,
      redacted: redactSecret(token),
      message: `JWT uses 'none' algorithm — signature verification bypass`,
      remediation: `Remove the 'none' algorithm JWT or replace with a properly signed token using HS256/RS256 with a strong secret.`
    });
  }

  // Check for Supabase Service Role Key
  if (payload.role === 'service_role') {
    findings.push({
      type: 'Supabase Service Role Key',
      confidence: 'high',
      file: filePath,
      line: lineNumber,
      redacted: redactSecret(token),
      message: `Supabase Service Role Key detected — bypasses Row Level Security`, 
      remediation: `Rotate this key immediately in Supabase dashboard. Replace with a restricted key or use Row Level Security policies.`
    });
  } else if (payload.role === 'anon') {
    findings.push({
      type: 'Supabase Anon Key',
      confidence: 'low',
      file: filePath,
      line: lineNumber,
      redacted: redactSecret(token),
      message: `Supabase Anon Key detected — limited access but may expose database structure`, 
      remediation: `Consider using Row Level Security policies to restrict access further.`
    });
  }
    
    // Check 2: HS256 with secret exposed nearby
    if (header.alg === 'HS256') {
      const secretExposed = checkForNearbySecret(fullContent, lines, lineNumber, token);
      if (secretExposed) {
        findings.push({
          type: 'JWT Secret Exposed',
          confidence: 'high',
          file: filePath,
          line: lineNumber,
          redacted: redactSecret(token),
          message: `JWT secret exposed alongside token — HS256 secret found in same file`,
          remediation: `Remove the secret from source code. Store JWT secrets in environment variables or secure secret management systems.`
        });
      }
    }
    
    // Check 3: Missing expiration
    if (!payload.exp) {
      findings.push({
        type: 'JWT No Expiration',
        confidence: 'medium',
        file: filePath,
        line: lineNumber,
        redacted: redactSecret(token),
        message: `JWT has no expiration — tokens never expire`,
        remediation: `Add an expiration (exp) claim to limit token lifetime. Consider using short-lived tokens with refresh tokens.`
      });
    } else {
      // Check 4: Unusually long expiry
      if (payload.iat) {
        const expInSeconds = payload.exp - payload.iat;
        const expInDays = expInSeconds / (60 * 60 * 24);
        
        if (expInDays > 30 && payload.role !== 'anon') {
          findings.push({
            type: 'JWT Long Expiry',
            confidence: 'low',
            file: filePath,
            line: lineNumber,
            redacted: redactSecret(token),
            message: `JWT expiry unusually long (${Math.round(expInDays)} days)`,
            remediation: `Consider reducing JWT expiration time. Long-lived tokens increase risk if compromised.`
          });
        }
      }
    }
    
  } catch (error) {
    // Not a valid JWT or other error - ignore
  }
  
  return findings;
}

/**
 * Check if there's a likely JWT secret near the token in the same file
 */
function checkForNearbySecret(fullContent, lines, tokenLineNumber, token) {
  // Look in a window around the token (±10 lines)
  const startLine = Math.max(0, tokenLineNumber - 11); // -1 for 0-based indexing
  const endLine = Math.min(lines.length, tokenLineNumber + 10);
  
  // Secret patterns to look for
  const secretPatterns = [
    /(?:jwt[_-]?secret|secret[_-]?key|jwt[_-]?key)\s*[:=]\s*['"]([^'"]+)['"]/gi,
    /['"]([a-zA-Z0-9_-]{32,})['"]/g, // Long random strings that could be secrets
    /(?:process\.env\.|env\.|getEnv\(|config\.)[a-zA-Z_][a-zA-Z0-9_]*(?:\s*[:=]|\s*\+\s*)/g // Env var usage
  ];
  
  // Check surrounding lines
  for (let i = startLine; i < endLine; i++) {
    const line = lines[i];
    
    // Skip the line containing the token itself to avoid matching parts of the JWT
    if (line.includes(token)) continue;
    
    // Check for explicit secret assignments
    for (const pattern of secretPatterns.slice(0, 2)) {
      if (pattern.test(line)) {
        return true;
      }
    }
  }
  
  return false;
}

module.exports = {
  scanJWT
};