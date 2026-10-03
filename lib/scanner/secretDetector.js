const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const { calculateEntropy, isBase64Charset, isHexCharset } = require('./entropy');
const { scanWithAST, shouldUseAST } = require('./astScanner');
// Ported from temp-test copy: real fileWalker.js only exports scanDirectory
// (it skips files >2MB in scanDirectory), so fall back to 10MB to keep direct
// detectSecrets() calls on large files on the streaming path.
const { STREAMING_THRESHOLD: _FW_STREAMING_THRESHOLD } = require('./fileWalker');
const STREAMING_THRESHOLD = _FW_STREAMING_THRESHOLD || (10 * 1024 * 1024);

// Secret detection patterns - organized for easy expansion
const SECRET_PATTERNS = [
  // AWS
  {
    name: 'AWS Access Key',
    pattern: /AKIA[0-9A-Z]{16}/g,
    confidence: 'high'
  },
  {
    name: 'AWS Secret Access Key',
    pattern: /(?:aws_secret|aws.?secret.?access.?key|secret.?key).{0,20}[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi,
    confidence: 'high'
  },
  
  // Supabase
  {
    name: 'Supabase Public Key',
    pattern: /sbp_[a-zA-Z0-9]{40}/g,
    confidence: 'high'
  },
  {
    name: 'Supabase Service Role Key',
    pattern: /(?:supabase|service.?role).{0,30}[=:]\s*['"]?(eyJ[a-zA-Z0-9_-]{20,}\.eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,})['"]?/gi,
    confidence: 'high'
  },
  
  // Stripe
  {
    name: 'Stripe Live Secret Key',
    pattern: /sk_live_[0-9a-zA-Z]{24,}/g,
    confidence: 'high'
  },
  {
    name: 'Stripe Live Restricted Key',
    pattern: /rk_live_[0-9a-zA-Z]{24,}/g,
    confidence: 'high'
  },
  {
    name: 'Stripe Test Secret Key',
    pattern: /sk_test_[0-9a-zA-Z]{24,}/g,
    confidence: 'medium'
  },
  {
    name: 'Stripe Test Restricted Key',
    pattern: /rk_test_[0-9a-zA-Z]{24,}/g,
    confidence: 'medium'
  },
  
  // OpenAI
  {
    name: 'OpenAI API Key',
    pattern: /sk-[a-zA-Z0-9]{20,}/g,
    confidence: 'high'
  },
  {
    name: 'OpenAI Project API Key',
    pattern: /sk-proj-[a-zA-Z0-9_-]{20,}/g,
    confidence: 'high'
  },
  
  // Anthropic
  {
    name: 'Anthropic API Key',
    pattern: /sk-ant-[a-zA-Z0-9_-]{20,}/g,
    confidence: 'high'
  },
  
  // Twilio
  {
    name: 'Twilio Account SID',
    pattern: /AC[0-9a-fA-F]{32}/g,
    confidence: 'high'
  },
  {
    name: 'Twilio Auth Token',
    pattern: /(?:twilio|auth.?token).{0,20}[=:]\s*['"]?([0-9a-fA-F]{32})['"]?/gi,
    confidence: 'high'
  },
  
  // GitHub
  {
    name: 'GitHub Personal Access Token',
    pattern: /ghp_[0-9a-zA-Z]{36}/g,
    confidence: 'high'
  },
  {
    name: 'GitHub OAuth Token',
    pattern: /gho_[0-9a-zA-Z]{36}/g,
    confidence: 'high'
  },
  {
    name: 'GitHub Fine-grained PAT',
    pattern: /github_pat_[0-9a-zA-Z_]{22,}/g,
    confidence: 'high'
  },
  
  // Slack
  {
    name: 'Slack Token',
    pattern: /xox[baprs]-[0-9a-zA-Z-]{10,}/g,
    confidence: 'high'
  },
  
  // Google
  {
    name: 'Google API Key',
    pattern: /AIza[0-9A-Za-z_-]{35}/g,
    confidence: 'high'
  },
  
  // Database Connection Strings
  {
    name: 'Database Connection String',
    pattern: /(postgres|postgresql|mysql|mongodb(\+srv)?):\/\/[^:]+:[^@]+@/gi,
    confidence: 'high'
  },
  
  // JWT (generic - medium confidence only)
  {
    name: 'JWT Token',
    pattern: /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g,
    confidence: 'medium',
    requiresContext: true
  },
  
  // Private Keys
  {
    name: 'Private Key',
    pattern: /-----BEGIN (?:RSA )?PRIVATE KEY-----/g,
    confidence: 'high'
  },
  
  // Generic API Key (requires context)
  {
    name: 'Generic API Key',
    pattern: /(?:api[_-]?key|apikey|secret|token)\s*[=:]\s*['"]([a-zA-Z0-9_\-]{16,})['"]?/gi,
    confidence: 'medium'
  }
];

// False positive detection helpers
const PLACEHOLDER_KEYWORDS = ['example', 'placeholder', 'dummy', 'fake', 'test', 'your-key-here', 'sample', 'xxx', 'yyy', 'zzz'];
const TEST_DIRECTORY_PATTERNS = ['test-fixtures/', '__tests__/', '__mocks__/', 'fixtures/', 'examples/'];

function isPlaceholderValue(value) {
  const lower = value.toLowerCase();
  
  // Check for placeholder keywords in the value itself
  // But be more specific - only flag if it's clearly a placeholder
  const strongPlaceholders = ['your-key-here', 'your_key_here', 'placeholder', 'replace_this', 'replace-this'];
  if (strongPlaceholders.some(keyword => lower.includes(keyword))) {
    return true;
  }
  
  // AWS-specific: keys ending in "EXAMPLE" are official AWS placeholders
  if (value.startsWith('AKIA') && value.endsWith('EXAMPLE')) {
    return true;
  }
  
  // Strip common prefixes to check the actual secret part.
  // Set SHRINE_NO_PREFIX_FILTER=true to skip prefix stripping (debug/compat).
  let secretPart = value;
  const noPrefixFilter = process.env.SHRINE_NO_PREFIX_FILTER === 'true' || process.env.SHRINE_NO_PREFIX_FILTER === '1';
  if (!noPrefixFilter) {
  const prefixPatterns = [
    /^sk_live_/, /^sk_test_/, /^rk_live_/, /^rk_test_/,
    /^sk-proj-/, /^sk-/, /^sk-ant-/,
    /^ghp_/, /^gho_/, /^github_pat_/,
    /^xox[baprs]-/,
    /^AIza/,
    /^AC[0-9a-fA-F]{0,6}/,
    /^AKIA/
  ];
  
  for (const prefix of prefixPatterns) {
    secretPart = secretPart.replace(prefix, '');
  }
  }
  
  // All zeros
  if (/^0+$/.test(secretPart)) {
    return true;
  }
  
  // All Xs (case insensitive)
  if (/^x+$/i.test(secretPart)) {
    return true;
  }
  
  // Repeated single character (for strings longer than 8 chars)
  if (secretPart.length > 8 && /^(.)\1+$/.test(secretPart)) {
    return true;
  }
  
  // Sequential characters like 1234567890 (digits only; alpha sequences
  // like AbCdEfGhIj are valid key material, e.g. OpenAI sk- keys)
  if (/^(0123456789|1234567890)/.test(secretPart)) {
    return true;
  }
  
  return false;
}

function isInCommentWithPlaceholder(line, previousLine) {
  const combinedContext = `${previousLine || ''} ${line}`.toLowerCase();
  
  // Check if it's in a comment
  const isComment = /^\s*(\/\/|#|\/\*|\*|<!--)/.test(line.trim());
  
  if (isComment) {
    // Check if the comment contains placeholder keywords
    return PLACEHOLDER_KEYWORDS.some(keyword => combinedContext.includes(keyword));
  }
  
  return false;
}

function isInTestDirectory(filePath, includeTests) {
  if (includeTests) {
    return false; // Don't filter if --include-tests is set
  }
  
  const normalizedPath = filePath.replace(/\\/g, '/');
  return TEST_DIRECTORY_PATTERNS.some(pattern => normalizedPath.includes(pattern));
}

function hasRequiredContext(line, previousLine, patternName) {
  // Only JWT and potentially other patterns marked with requiresContext need this check
  const contextKeywords = ['key', 'secret', 'token', 'password', 'credential', 'auth'];
  const combinedContext = `${previousLine || ''} ${line}`.toLowerCase();
  
  // Use word boundaries to match keywords as standalone words or with common separators
  return contextKeywords.some(keyword => {
    const regex = new RegExp(`\\b${keyword}\\b|[_-]${keyword}[_-]?|${keyword}[_-]`, 'i');
    return regex.test(combinedContext);
  });
}

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
 * Stream-based secret detection for large files
 * Reads file in chunks with overlap to catch secrets spanning chunk boundaries
 * Optimized with pattern prefix filtering for speed
 * (ported from temp-test copy; SHRINE_NO_PREFIX_FILTER bypasses the filter)
 */
async function detectSecretsStreaming(filePath, scanRoot, options = {}, fileSize) {
  const findings = [];
  const relativePath = path.relative(scanRoot, filePath);
  const fileName = path.basename(filePath);
  const verbose = options.verbose || false;

  const CHUNK_SIZE = 1024 * 1024; // 1MB chunks

  // Build prefix filters for quick line rejection
  const prefixFilters = buildPrefixFilters();

  return new Promise((resolve, reject) => {
    const stream = fsSync.createReadStream(filePath, { encoding: 'utf-8' });
    let buffer = '';
    let lineNumber = 1;
    let previousLine = '';
    let chunkCount = 0;

    stream.on('data', (chunk) => {
      chunkCount++;
      buffer += chunk;

      // Process complete lines
      const lines = buffer.split('\n');
      // Keep the last incomplete line in buffer
      buffer = lines.pop() || '';

      for (const line of lines) {
        // Quick rejection: skip lines that don't match any pattern prefix
        if (!hasPatternPrefix(line, prefixFilters) && !process.env.SHRINE_NO_PREFIX_FILTER) {
          previousLine = line;
          lineNumber++;
          continue;
        }

        // Special handling for .env files
        if (fileName === '.env' || fileName.startsWith('.env.')) {
          const trimmed = line.trim();
          if (trimmed && !trimmed.startsWith('#') && trimmed.includes('=')) {
            const [key, ...valueParts] = trimmed.split('=');
            const value = valueParts.join('=').trim();

            if (key.trim() && value && !isPlaceholderValue(value)) {
              findings.push({
                file: relativePath,
                line: lineNumber,
                type: 'Committed .env value',
                match: trimmed,
                redacted: `${key.trim()}=${redactSecret(value)}`,
                confidence: 'high'
              });
            }
          }
        }

        // Run all regex patterns
        for (const pattern of SECRET_PATTERNS) {
          pattern.pattern.lastIndex = 0;

          let match;
          while ((match = pattern.pattern.exec(line)) !== null) {
            const matchedSecret = match[1] || match[0];

            if (isPlaceholderValue(matchedSecret)) {
              continue;
            }

            if (isInCommentWithPlaceholder(line, previousLine)) {
              continue;
            }

            if (pattern.requiresContext && !hasRequiredContext(line, previousLine, pattern.name)) {
              continue;
            }

            findings.push({
              file: relativePath,
              line: lineNumber,
              type: pattern.name,
              match: matchedSecret,
              redacted: redactSecret(matchedSecret),
              confidence: pattern.confidence
            });
          }
        }

        // Entropy detection
        if (options.useEntropy) {
          const candidates = extractEntropyCandidates(line);

          for (const candidate of candidates) {
            const alreadyMatched = findings.some(f =>
              f.line === lineNumber && f.match === candidate
            );
            if (alreadyMatched) {
              continue;
            }

            const entropy = calculateEntropy(candidate);

            let isHighEntropy = false;
            if (isBase64Charset(candidate) && entropy > 4.5) {
              isHighEntropy = true;
            } else if (isHexCharset(candidate) && entropy > 3.0) {
              isHighEntropy = true;
            }

            if (!isHighEntropy) {
              continue;
            }

            if (!hasRequiredContext(line, previousLine)) {
              continue;
            }

            if (isPlaceholderValue(candidate) || isInCommentWithPlaceholder(line, previousLine)) {
              continue;
            }

            findings.push({
              file: relativePath,
              line: lineNumber,
              type: 'High Entropy String',
              match: candidate,
              redacted: redactSecret(candidate),
              confidence: 'medium',
              entropy: entropy.toFixed(2)
            });
          }
        }

        previousLine = line;
        lineNumber++;
      }
    });

    stream.on('end', () => {
      // Process any remaining content in buffer
      if (buffer) {
        const line = buffer;

        // Quick prefix check for last line
        if (hasPatternPrefix(line, prefixFilters) || process.env.SHRINE_NO_PREFIX_FILTER) {
          if (fileName === '.env' || fileName.startsWith('.env.')) {
            const trimmed = line.trim();
            if (trimmed && !trimmed.startsWith('#') && trimmed.includes('=')) {
              const [key, ...valueParts] = trimmed.split('=');
              const value = valueParts.join('=').trim();

              if (key.trim() && value && !isPlaceholderValue(value)) {
                findings.push({
                  file: relativePath,
                  line: lineNumber,
                  type: 'Committed .env value',
                  match: trimmed,
                  redacted: `${key.trim()}=${redactSecret(value)}`,
                  confidence: 'high'
                });
              }
            }
          }

          for (const pattern of SECRET_PATTERNS) {
            pattern.pattern.lastIndex = 0;

            let match;
            while ((match = pattern.pattern.exec(line)) !== null) {
              const matchedSecret = match[1] || match[0];

              if (!isPlaceholderValue(matchedSecret) &&
                  !isInCommentWithPlaceholder(line, previousLine) &&
                  (!pattern.requiresContext || hasRequiredContext(line, previousLine, pattern.name))) {
                findings.push({
                  file: relativePath,
                  line: lineNumber,
                  type: pattern.name,
                  match: matchedSecret,
                  redacted: redactSecret(matchedSecret),
                  confidence: pattern.confidence
                });
              }
            }
          }
        }
      }

      if (verbose && findings.length > 0) {
        console.log(`Streamed ${chunkCount} chunks, found ${findings.length} potential secret(s) in ${relativePath}`);
      }

      resolve(findings);
    });

    stream.on('error', (error) => {
      if (verbose) {
        console.log(`Could not stream file ${relativePath}: ${error.message}`);
      }
      resolve([]); // Return empty findings on error
    });
  });
}

/**
 * Build prefix filters for quick line rejection
 * Returns a set of string prefixes that indicate a line might contain secrets
 */
function buildPrefixFilters() {
  const prefixes = new Set([
    // OpenAI patterns
    'sk-',
    // AWS patterns
    'AKIA', 'aws', 'AWS',
    // Supabase
    'sbp_', 'eyJ', 'supabase', 'service',
    // Stripe
    'sk_live', 'sk_test', 'rk_live', 'rk_test',
    // OpenAI/Anthropic
    'sk-', 'sk-proj', 'sk-ant',
    // Twilio
    'AC', 'twilio', 'auth',
    // GitHub
    'ghp_', 'gho_', 'github_pat',
    // Slack
    'xox',
    // Google
    'AIza',
    // Database
    'postgres', 'mysql', 'mongodb',
    // Private keys
    '-----BEGIN',
    // Generic patterns
    'api', 'API', 'key', 'KEY', 'secret', 'SECRET', 'token', 'TOKEN', 'password', 'PASSWORD',
    // Assignment operators
    '=', ':'
  ]);
  return prefixes;
}

/**
 * Quick check if a line contains any pattern prefix
 * This allows us to skip lines that definitely don't contain secrets.
 * SHRINE_NO_PREFIX_FILTER=true|1 disables the filter (always returns true).
 */
function hasPatternPrefix(line, prefixFilters) {
  if (process.env.SHRINE_NO_PREFIX_FILTER) {
    return true;
  }
  // Quick length check - secrets are usually at least 8 chars
  if (line.length < 8) {
    return false;
  }

  // Check if line contains any of our prefix indicators
  for (const prefix of prefixFilters) {
    if (line.includes(prefix)) {
      return true;
    }
  }

  return false;
}

async function detectSecrets(filePath, scanRoot, options = {}) {
  const findings = [];
  const relativePath = path.relative(scanRoot, filePath);
  const fileName = path.basename(filePath);
  const verbose = options.verbose || false;
  const includeTests = options.includeTests || false;
  const useAST = options.useAST !== false; // Enabled by default
  
  // Skip test directories unless --include-tests is set
  if (isInTestDirectory(relativePath, includeTests)) {
    if (verbose) {
      console.log(`Skipping test directory file: ${relativePath}`);
    }
    return findings;
  }
  
  try {
    // Check file size and use streaming for large files
    const stats = await fs.stat(filePath);
    const fileSize = stats.size;

    if (fileSize > STREAMING_THRESHOLD) {
      if (verbose) {
        console.log(`Streaming large file (${(fileSize / (1024 * 1024)).toFixed(2)} MB): ${relativePath}`);
      }
      return await detectSecretsStreaming(filePath, scanRoot, options, fileSize);
    }

    const content = await fs.readFile(filePath, 'utf-8');
    
    // Try AST scanning for JS/TS files (unless disabled with --no-ast)
    if (useAST && shouldUseAST(filePath)) {
      if (verbose) {
        console.log(`Using AST scan for ${relativePath}`);
      }
      
      const astFindings = await scanWithAST(content, SECRET_PATTERNS, options);
      
      // If AST parsing succeeded, use those findings
      if (astFindings !== null) {
        // Add file path to each finding
        for (const finding of astFindings) {
          findings.push({
            ...finding,
            file: relativePath
          });
        }
        
        if (verbose) {
          console.log(`AST scan completed for ${relativePath}: ${astFindings.length} findings`);
        }
        
        return findings;
      }
      
      // If AST parsing failed, fall through to regex/entropy scanning
      if (verbose) {
        console.log(`Falling back to regex scan for ${relativePath}`);
      }
    }
    
    // Regular line-based scanning for non-JS files or when AST is disabled/failed
    const lines = content.split('\n');
    
    // Special handling for .env files - flag ALL non-empty key=value pairs
    if (fileName === '.env' || fileName.startsWith('.env.')) {
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        // Match KEY=value pattern, skip comments and empty lines
        if (line && !line.startsWith('#') && line.includes('=')) {
          const [key, ...valueParts] = line.split('=');
          const value = valueParts.join('=').trim();
          
          if (key.trim() && value) {
            // Check for placeholder values
            if (isPlaceholderValue(value)) {
              if (verbose) {
                console.log(`Skipping placeholder value in ${relativePath}:${i + 1}`);
              }
              continue;
            }
            
            findings.push({
              file: relativePath,
              line: i + 1,
              type: 'Committed .env value',
              match: line,
              redacted: `${key.trim()}=${redactSecret(value)}`,
              confidence: 'high'
            });
          }
        }
      }
    }
    
    // Run all regex patterns on each line
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const previousLine = i > 0 ? lines[i - 1] : '';
      
      for (const pattern of SECRET_PATTERNS) {
        // Reset regex lastIndex for global patterns
        pattern.pattern.lastIndex = 0;
        
        let match;
        while ((match = pattern.pattern.exec(line)) !== null) {
          const matchedSecret = match[1] || match[0];
          
          // False positive checks
          
          // 1. Check if it's a placeholder value
          if (isPlaceholderValue(matchedSecret)) {
            if (verbose) {
              console.log(`Skipping placeholder value in ${relativePath}:${i + 1}`);
            }
            continue;
          }
          
          // 2. Check if it's in a comment with placeholder keywords
          if (isInCommentWithPlaceholder(line, previousLine)) {
            if (verbose) {
              console.log(`Skipping comment placeholder in ${relativePath}:${i + 1}`);
            }
            continue;
          }
          
          // 3. Check if pattern requires context (JWT, generic hex strings)
          if (pattern.requiresContext && !hasRequiredContext(line, previousLine, pattern.name)) {
            if (verbose) {
              console.log(`Skipping match without context in ${relativePath}:${i + 1}`);
            }
            continue;
          }
          
          // 4. Supabase Service Role Key: decode JWT and check role claim
          if (pattern.name === 'Supabase Service Role Key') {
            try {
              const parts = matchedSecret.split('.');
              if (parts.length === 3) {
                // Base64url decode the payload (second segment)
                const payload = parts[1];
                const decoded = Buffer.from(payload.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf-8');
                const payloadObj = JSON.parse(decoded);
                
                // Only flag if role is service_role
                if (payloadObj.role !== 'service_role') {
                  if (verbose) {
                    console.log(`Skipping Supabase JWT with role=${payloadObj.role} in ${relativePath}:${i + 1}`);
                  }
                  continue;
                }
              }
            } catch (error) {
              // If decoding fails, skip this match
              if (verbose) {
                console.log(`Skipping invalid Supabase JWT in ${relativePath}:${i + 1}`);
              }
              continue;
            }
          }
          
          findings.push({
            file: relativePath,
            line: i + 1,
            type: pattern.name,
            match: matchedSecret,
            redacted: redactSecret(matchedSecret),
            confidence: pattern.confidence
          });
        }
      }
    }
    
    // Entropy-based detection (if enabled)
    if (options.useEntropy) {
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const previousLine = i > 0 ? lines[i - 1] : '';
        
        // Extract candidate substrings from the line
        const candidates = extractEntropyCandidates(line);
        
        for (const candidate of candidates) {
          // Skip if already matched by regex patterns
          const alreadyMatched = findings.some(f => 
            f.line === i + 1 && f.match === candidate
          );
          if (alreadyMatched) {
            continue;
          }
          
          // Calculate entropy
          const entropy = calculateEntropy(candidate);
          
          // Determine if it meets entropy threshold
          let isHighEntropy = false;
          if (isBase64Charset(candidate) && entropy > 4.5) {
            isHighEntropy = true;
          } else if (isHexCharset(candidate) && entropy > 3.0) {
            isHighEntropy = true;
          }
          
          if (!isHighEntropy) {
            continue;
          }
          
          // Require contextual keywords
          if (!hasRequiredContext(line, previousLine)) {
            if (verbose) {
              console.log(`Skipping high-entropy string without context in ${relativePath}:${i + 1}`);
            }
            continue;
          }
          
          // Apply false positive filters
          if (isPlaceholderValue(candidate)) {
            if (verbose) {
              console.log(`Skipping placeholder high-entropy value in ${relativePath}:${i + 1}`);
            }
            continue;
          }
          
          if (isInCommentWithPlaceholder(line, previousLine)) {
            if (verbose) {
              console.log(`Skipping high-entropy comment placeholder in ${relativePath}:${i + 1}`);
            }
            continue;
          }
          
          findings.push({
            file: relativePath,
            line: i + 1,
            type: 'High Entropy String',
            match: candidate,
            redacted: redactSecret(candidate),
            confidence: 'medium',
            entropy: entropy.toFixed(2)
          });
        }
      }
    }
    
    if (verbose && findings.length > 0) {
      console.log(`Found ${findings.length} potential secret(s) in ${relativePath}`);
    }
    
  } catch (error) {
    if (verbose) {
      console.log(`Could not read file ${relativePath}: ${error.message}`);
    }
  }
  
  return findings;
}

/**
 * Extract candidate substrings for entropy analysis
 * Looks for quoted strings and standalone tokens of 20+ alphanumeric/base64-safe chars
 */
function extractEntropyCandidates(line) {
  const candidates = [];
  
  // Extract quoted strings (single and double quotes)
  const quotedStrings = line.match(/["']([A-Za-z0-9+/=_-]{20,})["']/g);
  if (quotedStrings) {
    for (const quoted of quotedStrings) {
      // Remove the quotes
      const cleaned = quoted.substring(1, quoted.length - 1);
      candidates.push(cleaned);
    }
  }
  
  // Extract standalone tokens (20+ base64-safe characters)
  const tokens = line.match(/[A-Za-z0-9+/=_-]{20,}/g);
  if (tokens) {
    for (const token of tokens) {
      // Avoid duplicates from quoted strings
      if (!candidates.includes(token)) {
        candidates.push(token);
      }
    }
  }
  
  return candidates;
}

module.exports = { detectSecrets, SECRET_PATTERNS };
