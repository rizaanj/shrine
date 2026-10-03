const childProcess = require('child_process');
const path = require('path');

/**
 * Scan a GitHub/GitLab PR and comment findings
 * @param {Object} options
 * @param {string|number} options.prNumber - PR/MR number
 * @param {string} options.provider - 'github' or 'gitlab' (auto-detect if omitted)
 * @param {boolean} options.verbose - Enable verbose output
 * @param {string} options.targetPath - Repository path
 * @returns {Promise<{blockMerge: boolean, exitCode: number, findings: {total: number, high: number}}>}
 */
async function scanPR(options = {}) {
  const { prNumber, verbose, targetPath } = options;
  let { provider } = options;

  // Auto-detect provider if not specified
  if (!provider) {
    provider = detectProvider();
  }

  if (verbose) {
    console.log(`Detected provider: ${provider}`);
  }

  // Checkout PR branch (read-only)
  checkoutPR(prNumber, provider, targetPath, verbose);

  // Run shrine scan
  const scanResult = runScan(targetPath, verbose);
  
  // Parse findings
  const findings = parseFindings(scanResult.stdout);
  const blockMerge = findings.high > 0;

  if (verbose) {
    console.log(`Findings: total=${findings.total}, high=${findings.high}`);
  }

  // Post comment
  postComment(prNumber, provider, findings, blockMerge, verbose);

  return {
    blockMerge,
    exitCode: scanResult.exitCode,
    findings
  };
}

/**
 * Detect CI provider by checking CLI availability
 * @returns {string} 'github' or 'gitlab'
 */
function detectProvider() {
  // Try GitHub CLI first
  const ghCheck = childProcess.spawnSync('gh', ['--version'], { encoding: 'utf8' });
  if (ghCheck.status === 0) {
    return 'github';
  }

  // Try GitLab CLI
  const glabCheck = childProcess.spawnSync('glab', ['--version'], { encoding: 'utf8' });
  if (glabCheck.status === 0) {
    return 'gitlab';
  }

  throw new Error('No gh/glab CLI found');
}

/**
 * Checkout PR branch
 * @param {string|number} prNumber - PR/MR number
 * @param {string} provider - 'github' or 'gitlab'
 * @param {string} targetPath - Repository path
 * @param {boolean} verbose - Verbose output
 */
function checkoutPR(prNumber, provider, targetPath, verbose) {
  let result;
  
  if (provider === 'github') {
    // Get remote URL first
    const remoteResult = childProcess.spawnSync('git', ['remote', 'get-url', 'origin'], {
      cwd: targetPath,
      encoding: 'utf8'
    });
    
    if (remoteResult.status !== 0) {
      throw new Error('PR checkout failed: ' + (remoteResult.stderr || 'git remote failed'));
    }
    
    const repoUrl = remoteResult.stdout.trim();
    
    result = childProcess.spawnSync('gh', ['pr', 'checkout', String(prNumber), '--repo', repoUrl], {
      cwd: targetPath,
      encoding: 'utf8'
    });
  } else if (provider === 'gitlab') {
    result = childProcess.spawnSync('glab', ['mr', 'checkout', String(prNumber)], {
      cwd: targetPath,
      encoding: 'utf8'
    });
  } else {
    throw new Error('Invalid provider: ' + provider);
  }

  if (result.status !== 0) {
    throw new Error('PR checkout failed: ' + (result.stderr || 'checkout failed'));
  }

  if (verbose) {
    console.log('PR checked out successfully');
  }
}

/**
 * Run shrine scan
 * @param {string} targetPath - Repository path
 * @param {boolean} verbose - Verbose output
 * @returns {{exitCode: number, stdout: string}}
 */
function runScan(targetPath, verbose) {
  const shrinePath = path.join(__dirname, '../../bin/shrine.js');
  
  const result = childProcess.spawnSync('node', [
    shrinePath,
    'scan',
    '--path', targetPath,
    '--skip-auth',
    '--no-deps',
    '--no-code-scan'
  ], {
    encoding: 'utf8',
    timeout: 120000,
    env: { ...process.env, SHRINE_DEV_SKIP_VALIDATION: '1' }
  });

  if (result.error) {
    throw new Error('Scan failed: ' + result.error.message);
  }

  if (verbose) {
    console.log('Scan completed with exit code:', result.status);
  }

  return {
    exitCode: result.status,
    stdout: result.stdout || ''
  };
}

/**
 * Parse findings from scan output
 * @param {string} stdout - Scan stdout
 * @returns {{total: number, high: number}}
 */
function parseFindings(stdout) {
  const totalMatch = stdout.match(/Total findings:\s*(\d+)/);
  const highMatch = stdout.match(/High severity:\s*(\d+)/);

  return {
    total: totalMatch ? parseInt(totalMatch[1], 10) : 0,
    high: highMatch ? parseInt(highMatch[1], 10) : 0
  };
}

/**
 * Post comment to PR
 * @param {string|number} prNumber - PR/MR number
 * @param {string} provider - 'github' or 'gitlab'
 * @param {{total: number, high: number}} findings - Findings summary
 * @param {boolean} blockMerge - Whether to block merge
 * @param {boolean} verbose - Verbose output
 */
function postComment(prNumber, provider, findings, blockMerge, verbose) {
  const status = blockMerge ? '❌ **BLOCK**: Critical/high findings detected' : '✅ Safe to merge';
  const commentBody = `## 🛡️ Shrine Security Scan

Total findings: ${findings.total}
High severity: ${findings.high}

${status}

Run \`shrine scan\` locally for details.`;

  // Escape double quotes
  const escapedBody = commentBody.replace(/"/g, '\\"');

  let result;
  if (provider === 'github') {
    result = childProcess.spawnSync('gh', ['pr', 'comment', String(prNumber), '--body', escapedBody], {
      encoding: 'utf8'
    });
  } else if (provider === 'gitlab') {
    result = childProcess.spawnSync('glab', ['mr', 'note', String(prNumber), '-m', escapedBody], {
      encoding: 'utf8'
    });
  }

  if (result.status !== 0) {
    console.warn('Comment failed: ' + result.stderr);
  } else if (verbose) {
    console.log('Comment posted successfully');
  }
}

module.exports = { scanPR };
