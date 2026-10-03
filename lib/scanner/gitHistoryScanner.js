const { simpleGit } = require('simple-git');
const { SECRET_PATTERNS } = require('./secretDetector');

// Reuse false positive detection logic
const PLACEHOLDER_KEYWORDS = ['example', 'placeholder', 'dummy', 'fake', 'test', 'your-key-here', 'sample', 'xxx', 'yyy', 'zzz'];
const TEST_DIRECTORY_PATTERNS = ['test-fixtures/', '__tests__/', '__mocks__/', 'fixtures/', 'examples/'];

function isPlaceholderValue(value) {
  const lower = value.toLowerCase();
  
  // Check for strong placeholder keywords that clearly indicate it's fake
  const strongPlaceholders = ['your-key-here', 'your_key_here', 'placeholder', 'replace_this', 'replace-this'];
  if (strongPlaceholders.some(keyword => lower.includes(keyword))) {
    return true;
  }
  
  // AWS-specific: keys ending in "EXAMPLE" are official AWS placeholders
  if (value.startsWith('AKIA') && value.endsWith('EXAMPLE')) {
    return true;
  }
  
  // Strip common prefixes to check the actual secret part
  let secretPart = value;
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
  
  if (/^(0123456789|abcdefghij|1234567890)/i.test(secretPart)) {
    return true;
  }
  
  return false;
}

function isInCommentWithPlaceholder(line, previousLine) {
  const combinedContext = `${previousLine || ''} ${line}`.toLowerCase();
  const isComment = /^\s*(\/\/|#|\/\*|\*|<!--|\+\s*(\/\/|#))/.test(line.trim());
  
  if (isComment) {
    return PLACEHOLDER_KEYWORDS.some(keyword => combinedContext.includes(keyword));
  }
  
  return false;
}

function isInTestDirectory(filePath, includeTests) {
  if (includeTests) {
    return false;
  }
  
  const normalizedPath = filePath.replace(/\\/g, '/');
  return TEST_DIRECTORY_PATTERNS.some(pattern => normalizedPath.includes(pattern));
}

function hasRequiredContext(line, previousLine) {
  const contextKeywords = ['key', 'secret', 'token', 'password', 'credential', 'auth'];
  const combinedContext = `${previousLine || ''} ${line}`.toLowerCase();
  
  return contextKeywords.some(keyword => combinedContext.includes(keyword));
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

function detectSecretsInDiff(diffLine, previousLine, pattern, options) {
  const findings = [];
  
  // Reset regex lastIndex for global patterns
  pattern.pattern.lastIndex = 0;
  
  let match;
  while ((match = pattern.pattern.exec(diffLine)) !== null) {
    const matchedSecret = match[1] || match[0];
    
    // False positive checks
    if (isPlaceholderValue(matchedSecret)) {
      if (options.verbose) {
        console.log(`Skipping placeholder value in git history`);
      }
      continue;
    }
    
    if (isInCommentWithPlaceholder(diffLine, previousLine)) {
      if (options.verbose) {
        console.log(`Skipping comment placeholder in git history`);
      }
      continue;
    }
    
    if (pattern.requiresContext && !hasRequiredContext(diffLine, previousLine)) {
      if (options.verbose) {
        console.log(`Skipping match without context in git history`);
      }
      continue;
    }
    
    findings.push({
      type: pattern.name,
      match: matchedSecret,
      redacted: redactSecret(matchedSecret),
      confidence: pattern.confidence
    });
  }
  
  return findings;
}

async function scanCommitDiff(git, commitHash, options, source = 'history') {
  const findings = [];
  const verbose = options.verbose || false;
  const includeTests = options.includeTests || false;
  
  try {
    // Get the diff for this commit
    const diff = await git.show([commitHash, '--format=', '--unified=0']);
    const lines = diff.split('\n');
    
    let currentFile = null;
    let previousLine = '';
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      // Track which file we're in
      if (line.startsWith('diff --git')) {
        const match = line.match(/diff --git a\/(.+?) b\/(.+)/);
        if (match) {
          currentFile = match[2]; // Use the "b/" path (after rename)
        }
      } else if (line.startsWith('+++')) {
        const match = line.match(/\+\+\+ b\/(.+)/);
        if (match) {
          currentFile = match[1];
        }
      }
      
      // Only scan added lines (starting with +, but not +++ file markers)
      if (line.startsWith('+') && !line.startsWith('+++')) {
        // Skip if in test directory
        if (currentFile && isInTestDirectory(currentFile, includeTests)) {
          continue;
        }
        
        // Remove the leading + for pattern matching
        const content = line.substring(1);
        
        // Run all patterns against this line
        for (const pattern of SECRET_PATTERNS) {
          const lineFindings = detectSecretsInDiff(content, previousLine, pattern, options);
          
          for (const finding of lineFindings) {
            findings.push({
              ...finding,
              commit: commitHash.substring(0, 7),
              file: currentFile || 'unknown',
              source // 'history', 'reflog', or 'orphaned'
            });
          }
        }
      }
      
      previousLine = line;
    }
  } catch (error) {
    if (verbose) {
      console.log(`Error processing commit ${commitHash}: ${error.message}`);
    }
  }
  
  return findings;
}

async function scanReflog(git, repoPath, scannedCommits, options) {
  const findings = [];
  const verbose = options.verbose || false;
  const { execSync } = require('child_process');
  
  try {
    if (verbose) {
      console.log('Scanning reflog for force-pushed/reset commits...');
    }
    
    // Run git reflog show --all to get all reflog entries
    const reflogOutput = execSync('git reflog show --all', { 
      cwd: repoPath, 
      encoding: 'utf-8',
      maxBuffer: 50 * 1024 * 1024 // 50MB buffer
    });
    
    // Extract commit SHAs from reflog
    const reflogCommits = new Set();
    const reflogLines = reflogOutput.split('\n');
    
    for (const line of reflogLines) {
      // Reflog format: <sha> <refname>@{<num>}: <action>
      const match = line.match(/^([0-9a-f]{7,40})\s+/);
      if (match) {
        const commitHash = match[1];
        // Only scan commits not already covered by normal history
        if (!scannedCommits.has(commitHash)) {
          reflogCommits.add(commitHash);
        }
      }
    }
    
    if (verbose) {
      console.log(`Found ${reflogCommits.size} additional commits in reflog to scan`);
    }
    
    // Scan each reflog-only commit
    for (const commitHash of reflogCommits) {
      const commitFindings = await scanCommitDiff(git, commitHash, options, 'reflog');
      findings.push(...commitFindings);
    }
    
  } catch (error) {
    if (verbose) {
      console.log(`Error scanning reflog: ${error.message}`);
    }
  }
  
  return findings;
}

async function scanOrphanedCommits(git, repoPath, scannedCommits, options) {
  const findings = [];
  const verbose = options.verbose || false;
  const { execSync } = require('child_process');
  
  try {
    if (verbose) {
      console.log('Scanning for orphaned/dangling commits...');
    }
    
    // Run git fsck --unreachable --no-reflogs to find orphaned commits
    const fsckOutput = execSync('git fsck --unreachable --no-reflogs', { 
      cwd: repoPath, 
      encoding: 'utf-8',
      maxBuffer: 50 * 1024 * 1024 // 50MB buffer
    });
    
    // Extract commit SHAs from fsck output
    const orphanedCommits = new Set();
    const fsckLines = fsckOutput.split('\n');
    
    for (const line of fsckLines) {
      // fsck format: unreachable commit <sha>
      const match = line.match(/^unreachable commit ([0-9a-f]{40})/);
      if (match) {
        const commitHash = match[1];
        // Only scan commits not already covered by normal history or reflog
        if (!scannedCommits.has(commitHash)) {
          orphanedCommits.add(commitHash);
        }
      }
    }
    
    if (verbose) {
      console.log(`Found ${orphanedCommits.size} orphaned commits to scan`);
    }
    
    // Scan each orphaned commit
    for (const commitHash of orphanedCommits) {
      const commitFindings = await scanCommitDiff(git, commitHash, options, 'orphaned');
      findings.push(...commitFindings);
    }
    
  } catch (error) {
    if (verbose) {
      console.log(`Error scanning orphaned commits: ${error.message}`);
    }
  }
  
  return findings;
}

async function scanGitHistory(repoPath, options = {}) {
  const git = simpleGit(repoPath);
  const findings = [];
  const verbose = options.verbose || false;
  const includeTests = options.includeTests || false;
  const depth = options.depth; // null means unlimited
  const deepHistory = options.deepHistory || false;
  
  try {
    // Check if this is a git repository
    const isRepo = await git.checkIsRepo();
    if (!isRepo) {
      if (verbose) {
        console.log('Not a git repository, skipping history scan');
      }
      return findings;
    }
    
    // Track which commits we've scanned to avoid duplicates
    const scannedCommits = new Set();
    
    // Get commit log
    const logOptions = depth ? { maxCount: depth } : {};
    const log = await git.log(logOptions);
    
    if (verbose) {
      console.log(`Scanning ${log.all.length} commits in git history`);
    }
    
    // Process each commit in normal history
    for (const commit of log.all) {
      scannedCommits.add(commit.hash);
      
      const commitFindings = await scanCommitDiff(git, commit.hash, options, 'history');
      
      // Add commit metadata
      for (const finding of commitFindings) {
        findings.push({
          ...finding,
          date: commit.date,
          author: commit.author_name
        });
      }
    }
    
    // If deep history is enabled, scan reflog and orphaned commits
    if (deepHistory) {
      if (verbose) {
        console.log('\nDeep history scan enabled - checking reflog and orphaned commits...');
      }
      
      // Scan reflog for force-pushed commits
      const reflogFindings = await scanReflog(git, repoPath, scannedCommits, options);
      
      // Add reflog commits to scanned set
      for (const finding of reflogFindings) {
        scannedCommits.add(finding.commit);
      }
      
      findings.push(...reflogFindings);
      
      // Scan for orphaned commits
      const orphanedFindings = await scanOrphanedCommits(git, repoPath, scannedCommits, options);
      findings.push(...orphanedFindings);
      
      if (verbose) {
        console.log(`Deep history scan complete: ${reflogFindings.length} reflog findings, ${orphanedFindings.length} orphaned findings`);
      }
    }
    
  } catch (error) {
    if (verbose) {
      console.log(`Error scanning git history: ${error.message}`);
    }
  }
  
  return findings;
}

module.exports = { scanGitHistory };
