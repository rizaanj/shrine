const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const { calculateEntropy, isBase64Charset, isHexCharset } = require('./entropy');

// Keywords that indicate a variable/property might contain secrets
const SECRET_KEYWORDS = ['key', 'secret', 'token', 'password', 'credential', 'auth', 'apikey', 'api_key'];

// Function names that often receive secrets as arguments
const SECRET_FUNCTION_PATTERNS = [
  /setapikey/i,
  /settoken/i,
  /setsecret/i,
  /authorization/i,
  /authenticate/i,
  /env/i
];

/**
 * Check if a name suggests it might contain a secret
 */
function isSecretLikeName(name) {
  if (!name) return false;
  const lower = name.toLowerCase();
  return SECRET_KEYWORDS.some(keyword => lower.includes(keyword));
}

/**
 * Check if a function name suggests it receives secrets
 */
function isSecretFunction(name) {
  if (!name) return false;
  return SECRET_FUNCTION_PATTERNS.some(pattern => pattern.test(name));
}

/**
 * Check if a string value is a template placeholder
 */
function isTemplatePlaceholder(value) {
  // Empty strings
  if (!value || value.length === 0) return true;
  
  // Pure interpolation like "${API_KEY}" or "${process.env.KEY}"
  if (/^\$\{[^}]+\}$/.test(value)) return true;
  
  return false;
}

/**
 * Boost confidence level based on AST context
 */
function boostConfidence(originalConfidence) {
  if (originalConfidence === 'medium') return 'high';
  return originalConfidence;
}

/**
 * Run pattern and entropy checks on a candidate string
 */
function checkSecretPatterns(value, secretPatterns, options = {}) {
  const findings = [];
  const useEntropy = options.useEntropy || false;
  
  // Run regex patterns
  for (const pattern of secretPatterns) {
    pattern.pattern.lastIndex = 0;
    let match;
    while ((match = pattern.pattern.exec(value)) !== null) {
      const matchedSecret = match[1] || match[0];
      findings.push({
        type: pattern.name,
        match: matchedSecret,
        confidence: boostConfidence(pattern.confidence)
      });
    }
  }
  
  // Run entropy check if enabled and no patterns matched
  if (useEntropy && findings.length === 0 && value.length >= 20) {
    const entropy = calculateEntropy(value);
    let isHighEntropy = false;
    
    if (isBase64Charset(value) && entropy > 4.5) {
      isHighEntropy = true;
    } else if (isHexCharset(value) && entropy > 3.0) {
      isHighEntropy = true;
    }
    
    if (isHighEntropy) {
      findings.push({
        type: 'High Entropy String',
        match: value,
        confidence: 'high', // Boosted from medium due to AST context
        entropy: entropy.toFixed(2)
      });
    }
  }
  
  return findings;
}

/**
 * Get line number from AST node location
 */
function getLineNumber(node) {
  return node.loc ? node.loc.start.line : 0;
}

/**
 * Redact a secret for display
 */
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
 * Scan JS/TS file using AST parsing
 */
async function scanWithAST(content, secretPatterns, options = {}) {
  const findings = [];
  const verbose = options.verbose || false;
  const useEntropy = options.useEntropy || false;
  
  try {
    // Parse the code into an AST
    const ast = parser.parse(content, {
      sourceType: 'module',
      plugins: ['jsx', 'typescript', 'decorators-legacy', 'classProperties', 'objectRestSpread']
    });
    
    // Traverse the AST
    traverse(ast, {
      // Variable declarations: const apiKey = "..."
      VariableDeclarator(path) {
        const node = path.node;
        
        // Check if variable name suggests a secret
        if (node.id && node.id.name && isSecretLikeName(node.id.name)) {
          // Check if initializer is a string literal
          if (node.init && node.init.type === 'StringLiteral') {
            const value = node.init.value;
            
            // Skip template placeholders
            if (isTemplatePlaceholder(value)) {
              return;
            }
            
            // Check for secret patterns
            const matches = checkSecretPatterns(value, secretPatterns, { useEntropy });
            for (const match of matches) {
              findings.push({
                line: getLineNumber(node),
                type: match.type,
                match: match.match,
                redacted: redactSecret(match.match),
                confidence: match.confidence,
                context: `variable '${node.id.name}'`,
                entropy: match.entropy
              });
            }
          }
        }
      },
      
      // Object properties: { apiKey: "...", secret: "..." }
      ObjectProperty(path) {
        const node = path.node;
        
        // Get property name
        let propertyName = null;
        if (node.key.type === 'Identifier') {
          propertyName = node.key.name;
        } else if (node.key.type === 'StringLiteral') {
          propertyName = node.key.value;
        }
        
        // Check if property name suggests a secret
        if (propertyName && isSecretLikeName(propertyName)) {
          // Check if value is a string literal
          if (node.value && node.value.type === 'StringLiteral') {
            const value = node.value.value;
            
            // Skip template placeholders
            if (isTemplatePlaceholder(value)) {
              return;
            }
            
            // Check for secret patterns
            const matches = checkSecretPatterns(value, secretPatterns, { useEntropy });
            for (const match of matches) {
              findings.push({
                line: getLineNumber(node),
                type: match.type,
                match: match.match,
                redacted: redactSecret(match.match),
                confidence: match.confidence,
                context: `property '${propertyName}'`,
                entropy: match.entropy
              });
            }
          }
        }
      },
      
      // Function calls with string arguments: setApiKey("...")
      CallExpression(path) {
        const node = path.node;
        
        // Get function name
        let functionName = null;
        if (node.callee.type === 'Identifier') {
          functionName = node.callee.name;
        } else if (node.callee.type === 'MemberExpression' && node.callee.property) {
          functionName = node.callee.property.name || node.callee.property.value;
        }
        
        // Check if function name suggests it receives secrets
        if (functionName && isSecretFunction(functionName)) {
          // Check arguments for string literals
          for (const arg of node.arguments) {
            if (arg.type === 'StringLiteral') {
              const value = arg.value;
              
              // Skip template placeholders
              if (isTemplatePlaceholder(value)) {
                continue;
              }
              
              // Check for secret patterns
              const matches = checkSecretPatterns(value, secretPatterns, { useEntropy });
              for (const match of matches) {
                findings.push({
                  line: getLineNumber(node),
                  type: match.type,
                  match: match.match,
                  redacted: redactSecret(match.match),
                  confidence: match.confidence,
                  context: `argument to '${functionName}()'`,
                  entropy: match.entropy
                });
              }
            }
          }
        }
      }
    });
    
    if (verbose && findings.length > 0) {
      console.log(`AST scan found ${findings.length} potential secret(s)`);
    }
    
  } catch (error) {
    // Parse error - will fall back to regex scanning
    if (verbose) {
      console.log(`AST parse error: ${error.message} - falling back to regex scan`);
    }
    return null; // Signal fallback needed
  }
  
  return findings;
}

/**
 * Check if file should use AST scanning
 */
function shouldUseAST(filePath) {
  const ext = filePath.toLowerCase();
  return ext.endsWith('.js') || 
         ext.endsWith('.jsx') || 
         ext.endsWith('.ts') || 
         ext.endsWith('.tsx') ||
         ext.endsWith('.mjs') ||
         ext.endsWith('.cjs');
}

module.exports = {
  scanWithAST,
  shouldUseAST
};
