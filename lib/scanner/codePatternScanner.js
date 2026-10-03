const fs = require('fs').promises;
const path = require('path');

const SKIP_PATTERNS = [
  'node_modules/**',
  '**/*.min.js',
  '**/*.bundle.js',
];

const PATTERNS = [
  {
    type: 'XSS: innerHTML/outerHTML Assignment',
    regex: /\.(innerHTML|outerHTML)\s*=\s*[^;]+/g,
    severity: 'high',
    confidence: 'high',
    fixPrompt: 'Use textContent or sanitize input with DOMPurify before assigning to innerHTML/outerHTML.',
    skipInComments: true,
  },
  {
    type: 'XSS: dangerouslySetInnerHTML',
    regex: /dangerouslySetInnerHTML\s*:\s*\{[^}]*__html\s*:\s*[^}]+\}/g,
    severity: 'high',
    confidence: 'high',
    fixPrompt: 'Sanitize HTML content with DOMPurify before using dangerouslySetInnerHTML.',
    skipInComments: true,
  },
  {
    type: 'XSS: document.write',
    regex: /document\.write\s*\(\s*[^)]+\)/g,
    severity: 'high',
    confidence: 'medium',
    fixPrompt: 'Avoid document.write. Use DOM APIs or framework-safe rendering instead.',
    skipInComments: true,
  },
  {
    type: 'Injection: eval with non-literal',
    regex: /\beval\s*\(\s*(?![\"'`])[^)]+\)/g,
    severity: 'critical',
    confidence: 'high',
    fixPrompt: 'Never use eval with dynamic input. Use JSON.parse for JSON, or refactor to avoid dynamic code execution.',
    skipInComments: true,
  },
  {
    type: 'Injection: new Function with non-literal',
    regex: /new\s+Function\s*\(([^)]*)\)/g,
    severity: 'critical',
    confidence: 'high',
    fixPrompt: 'Avoid new Function with dynamic input. Use safe alternatives or static functions.',
    skipInComments: true,
    validator: (match, content) => {
      const args = match[1];
      // Check if any argument contains non-literal: variable, concat, template, or function call
      const parts = args.split(',').map(s => s.trim());
      return parts.some(arg => {
        // Skip string literals, numbers, true/false/null/undefined
        if (/^(["'`]).*\1$/.test(arg)) return false; // string literal
        if (/^\d+(\.\d+)?$/.test(arg)) return false; // number
        if (/^(true|false|null|undefined)$/.test(arg)) return false; // boolean/null/undefined
        // Check for variable references, operators, template strings, function calls
        if (/[a-zA-Z_$][\w$]*(?:\s*[+\-*/%&|^]\s*[a-zA-Z_$][\w$]*)+/.test(arg)) return true;
        if (/`[^`]*\$\{[^`]*`/.test(arg)) return true;
        if (/[a-zA-Z_$][\w$]*\s*\(/.test(arg)) return true;
        // Any identifier that's not a keyword
        if (/^[a-zA-Z_$][\w$]*$/.test(arg) && !/^(true|false|null|undefined)$/.test(arg)) return true;
        return false;
      });
    },
  },
  {
    type: 'Injection: child_process exec with template string',
    regex: /(exec|spawn|execSync|spawnSync)\s*\(\s*`[^`]*\$\{[^`]*`/g,
    severity: 'critical',
    confidence: 'high',
    fixPrompt: 'Use execFile/spawn with array arguments instead of shell command strings. Never interpolate user input into shell commands.',
    skipInComments: true,
  },
  {
    type: 'Injection: SQL concatenation/template literal',
    regex: /(query|execute|run|all|get)\s*\(\s*[^)]*(\+|`[^`]*\$\{[^`]*`)/g,
    severity: 'high',
    confidence: 'medium',
    fixPrompt: 'Use parameterized queries (placeholders) instead of string concatenation or template literals for SQL.',
    skipInComments: true,
    validator: (match, content) => {
      const line = match[0];
      // Require SQL-like keywords to reduce false positives on JS array access
      const sqlKeywords = /\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN|TABLE|VALUES|SET|ORDER BY|GROUP BY|HAVING|LIMIT|OFFSET|CREATE|DROP|ALTER|INDEX|PRIMARY KEY|FOREIGN KEY|REFERENCES)\b/i;
      return sqlKeywords.test(line);
    },
  },
  {
    type: 'Injection: Unsantized req.query/req.body in res.send/render',
    regex: /res\.(send|render|json|jsonp)\s*\(\s*req\.(query|body|params)/g,
    severity: 'high',
    confidence: 'low',
    fixPrompt: 'Validate and sanitize all user input before sending in response. Use a validation library like Joi or Zod. If validation middleware is present, this may be a false positive.',
    skipInComments: true,
  },
];

function isInComment(line, index, content) {
  const beforeIndex = content.substring(0, index).lastIndexOf('\n');
  const lineStart = beforeIndex === -1 ? 0 : beforeIndex + 1;
  const lineContent = content.substring(lineStart, index);
  
  const singleLineComment = lineContent.indexOf('//');
  if (singleLineComment !== -1) return true;
  
  const multiLineCommentStart = content.substring(0, index).lastIndexOf('/*');
  const multiLineCommentEnd = content.substring(0, index).lastIndexOf('*/');
  if (multiLineCommentStart > multiLineCommentEnd) return true;
  
  return false;
}

function getLineNumber(content, index) {
  return content.substring(0, index).split('\n').length;
}

function shouldSkipFile(filePath) {
  return SKIP_PATTERNS.some(pattern => {
    const regex = new RegExp(pattern.replace(/\*\*/g, '.*').replace(/\*/g, '[^/]*'));
    return regex.test(filePath);
  });
}

async function scanFileForPatterns(filePath) {
  const findings = [];
  
  if (shouldSkipFile(filePath)) {
    return findings;
  }
  
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    const lines = content.split('\n');
    
    for (const pattern of PATTERNS) {
      const matches = content.matchAll(pattern.regex);
      
      for (const match of matches) {
        if (pattern.skipInComments && isInComment(content, match.index, content)) {
          continue;
        }
        
        // Run validator if present
        if (pattern.validator && !pattern.validator(match, content)) {
          continue;
        }
        
        const lineNum = getLineNumber(content, match.index);
        const line = lines[lineNum - 1] || '';
        const redacted = line.trim().substring(0, 100);
        
        findings.push({
          type: pattern.type,
          file: filePath,
          line: lineNum,
          severity: pattern.severity,
          confidence: pattern.confidence,
          redacted: redacted,
          summary: pattern.type,
          fixPrompt: pattern.fixPrompt,
          match: match[0].substring(0, 200),
        });
      }
    }
  } catch (error) {
    console.warn(`Failed to scan ${filePath} for code patterns: ${error.message}`);
  }
  
  return findings;
}

async function scanDirectoryForPatterns(targetPath, verbose = false) {
  const fg = require('fast-glob');
  const findings = [];
  
  const files = await fg('**/*.{js,jsx,ts,tsx,json}', {
    cwd: targetPath,
    ignore: ['node_modules/**', '**/*.min.js', '**/*.bundle.js', '.git/**'],
    onlyFiles: true,
    absolute: true,
  });
  
  if (verbose) {
    console.log(`[codePatternScanner] Scanning ${files.length} files for XSS/injection patterns`);
  }
  
  for (const file of files) {
    const fileFindings = await scanFileForPatterns(file);
    findings.push(...fileFindings);
  }
  
  if (verbose) {
    console.log(`[codePatternScanner] Found ${findings.length} potential issues`);
  }
  
  return findings;
}

module.exports = { scanDirectoryForPatterns, PATTERNS };