const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

/**
 * Generate a fix for a finding
 * @param {Object} finding - The security finding to fix
 * @returns {Object|null} Fix object with {fixed, original, patched, description} or null if no fix available
 */
function generateFix(finding) {
  if (!finding || !finding.type) {
    return null;
  }

  const type = finding.type;

  // Cannot auto-fix: must rotate key
  if (type === 'Committed .env value') {
    return null;
  }

  // API Missing Auth
  if (type === 'API Missing Auth') {
    if (!finding.file || (!finding.file.endsWith('.js') && !finding.file.endsWith('.ts'))) {
      return null;
    }

    try {
      const content = fs.readFileSync(finding.file, 'utf-8');
      const lines = content.split('\n');
      
      if (!finding.line || finding.line < 1 || finding.line > lines.length) {
        return null;
      }

      const lineIndex = finding.line - 1;
      const original = lines[lineIndex];
      
      // Simple heuristic: insert auth check before route handler body
      // Look for function/arrow function pattern
      const indent = original.match(/^(\s*)/)?.[1] || '';
      const authCheck = `${indent}  if (!req.user) return res.status(401).json({error:'Unauthorized'});`;
      
      return {
        fixed: true,
        original: original,
        patched: original + '\n' + authCheck,
        description: 'Added auth check before route handler'
      };
    } catch (err) {
      return null;
    }
  }

  // XSS: innerHTML Assignment
  if (type === 'XSS: innerHTML Assignment') {
    if (!finding.file || !finding.line) {
      return null;
    }

    try {
      const content = fs.readFileSync(finding.file, 'utf-8');
      const lines = content.split('\n');
      
      if (finding.line < 1 || finding.line > lines.length) {
        return null;
      }

      const lineIndex = finding.line - 1;
      const original = lines[lineIndex];
      
      // Check if line contains innerHTML assignment
      if (!original.includes('.innerHTML')) {
        return null;
      }

      // Simple replacement: innerHTML -> textContent
      const patched = original.replace(/\.innerHTML\s*=/g, '.textContent =');
      
      if (patched === original) {
        return null; // No change made
      }

      return {
        fixed: true,
        original: original,
        patched: patched,
        description: 'Replaced innerHTML with textContent to prevent XSS'
      };
    } catch (err) {
      return null;
    }
  }

  // Injection: eval with non-literal
  if (type === 'Injection: eval with non-literal') {
    if (!finding.file || !finding.line) {
      return null;
    }

    try {
      const content = fs.readFileSync(finding.file, 'utf-8');
      const lines = content.split('\n');
      
      if (finding.line < 1 || finding.line > lines.length) {
        return null;
      }

      const lineIndex = finding.line - 1;
      const original = lines[lineIndex];
      
      // Look for eval() pattern
      const evalMatch = original.match(/eval\s*\(\s*([^)]+)\s*\)/);
      if (!evalMatch) {
        return null;
      }

      const expr = evalMatch[1].trim();
      
      // Only fix if expr looks JSON-ish (starts with { or [)
      const exprStart = expr.replace(/^['"`]+/, '').trim();
      if (!exprStart.startsWith('{') && !exprStart.startsWith('[')) {
        return null; // Too risky
      }

      const patched = original.replace(/eval\s*\(\s*([^)]+)\s*\)/, 'JSON.parse($1)');
      
      return {
        fixed: true,
        original: original,
        patched: patched,
        description: 'Replaced eval() with JSON.parse() for JSON data'
      };
    } catch (err) {
      return null;
    }
  }

  // RLS Disabled
  if (type === 'RLS Disabled') {
    const table = finding.table || finding.resource || 'unknown_table';
    return {
      fixed: false,
      original: '',
      patched: '',
      description: `Run: ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY;`
    };
  }

  // Default: no auto-fix available
  return null;
}

/**
 * Apply a fix to a file
 * @param {Object} finding - The security finding
 * @param {Object} fix - The fix object from generateFix
 * @returns {Object} {applied: boolean, error: string|null}
 */
function applyFix(finding, fix) {
  if (!fix || !fix.fixed) {
    return { applied: false, error: 'Fix is not applicable' };
  }

  if (!finding.file || !finding.line) {
    return { applied: false, error: 'Missing file or line information' };
  }

  let backupContent = null;

  try {
    // Read file
    const content = fs.readFileSync(finding.file, 'utf-8');
    backupContent = content;
    const lines = content.split('\n');

    if (finding.line < 1 || finding.line > lines.length) {
      return { applied: false, error: 'Invalid line number' };
    }

    const lineIndex = finding.line - 1;

    // Verify original matches
    if (lines[lineIndex] !== fix.original) {
      return { applied: false, error: 'Original line does not match current file content' };
    }

    // Apply fix
    if (fix.patched.includes('\n')) {
      // Multi-line replacement
      const patchedLines = fix.patched.split('\n');
      lines.splice(lineIndex, 1, ...patchedLines);
    } else {
      lines[lineIndex] = fix.patched;
    }

    const newContent = lines.join('\n');

    // Write back
    fs.writeFileSync(finding.file, newContent, 'utf-8');

    // Syntax check for JS/TS files
    if (finding.file.endsWith('.js') || finding.file.endsWith('.ts')) {
      const checkResult = spawnSync('node', ['--check', finding.file], {
        encoding: 'utf-8',
        timeout: 5000
      });

      if (checkResult.status !== 0) {
        // Rollback
        fs.writeFileSync(finding.file, backupContent, 'utf-8');
        return { 
          applied: false, 
          error: 'Syntax error after fix: ' + (checkResult.stderr || checkResult.stdout || 'unknown error')
        };
      }
    }

    return { applied: true, error: null };
  } catch (err) {
    // Attempt rollback if we have backup
    if (backupContent && finding.file) {
      try {
        fs.writeFileSync(finding.file, backupContent, 'utf-8');
      } catch (rollbackErr) {
        // Ignore rollback errors
      }
    }
    return { applied: false, error: err.message };
  }
}

module.exports = {
  generateFix,
  applyFix
};
