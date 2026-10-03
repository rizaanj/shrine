const chalk = require('chalk');
const { generateFixPrompts, displayFixPrompts } = require('./fixPromptGenerator');

function formatOutput(results) {
  // Handle both old and new API
  let workingDirFindings = [];
  let historyFindings = [];
  let supabaseFindings = [];
  let filesScanned = 0;
  let fixPrompts = false;
  let skipped = [];
  
  if (Array.isArray(results)) {
    // Old API: just an array of findings (backward compatibility)
    workingDirFindings = results;
    filesScanned = arguments[1] || 0;
  } else {
    // New API: object with workingDir, history, supabase, and filesScanned
    workingDirFindings = results.workingDir || [];
    historyFindings = results.history || [];
    supabaseFindings = results.supabase || [];
    filesScanned = results.filesScanned || 0;
    fixPrompts = results.fixPrompts || false;
    skipped = results.skipped || [];
  }

  const skippedLines = skipped.length > 0
    ? `\nSkipped ${skipped.length} file(s):\n` + skipped.map(entry => `  ${entry.path} (${entry.reason})`).join('\n') + '\n'
    : '';
  
  console.log('\n' + chalk.bold('=== Shrine Security Scan Results ===\n'));
  
  const hasWorkingDirFindings = workingDirFindings.length > 0;
  const hasHistoryFindings = historyFindings.length > 0;
  const hasSupabaseFindings = supabaseFindings.length > 0;
  
  if (!hasWorkingDirFindings && !hasHistoryFindings && !hasSupabaseFindings) {
    if (process.argv.includes('--sqli')) {
  console.log(chalk.green.bold('✓ No SQL injection vulnerabilities detected'));
} else {
  console.log(chalk.green.bold('✓ No exposed secrets or misconfigurations found'));
}
    console.log(chalk.gray(`\nScanned ${filesScanned} files\n`));
    if (skippedLines) console.log(chalk.gray(skippedLines));
    return 0;
  }
  
  let totalHighConfidence = 0;
  let totalMediumConfidence = 0;
  
  // Display working directory findings
  if (hasWorkingDirFindings) {
    console.log(chalk.bold.cyan('📁 Current Files\n'));
    
    const { display, highCount, mediumCount } = formatFindings(workingDirFindings, 'file');
    console.log(display);
    totalHighConfidence += highCount;
    totalMediumConfidence += mediumCount;
  }
  
  // Display git history findings
  if (hasHistoryFindings) {
    if (hasWorkingDirFindings) {
      console.log(chalk.bold('─'.repeat(60)) + '\n');
    }
    
    console.log(chalk.bold.yellow('⚠ Found in Git History\n'));
    console.log(chalk.gray('These secrets may still be exposed even if removed from current files.'));
    console.log(chalk.gray('Anyone who clones the repo can recover them. Recommend key rotation.\n'));
    
    // Check if we have deep history findings
    const hasDeepHistory = historyFindings.some(f => f.source === 'reflog' || f.source === 'orphaned');
    if (hasDeepHistory) {
      console.log(chalk.yellow.bold('Note: This scan only finds what\'s still present in YOUR local git object database.'));
      console.log(chalk.gray('If you cloned this repo fresh, force-pushed-away commits from before your clone'));
      console.log(chalk.gray('won\'t be here — check with someone who has the original history, or scan on'));
      console.log(chalk.gray('the machine where the force-push happened.\n'));
    }
    
    const { display, highCount, mediumCount } = formatHistoryFindings(historyFindings);
    console.log(display);
    totalHighConfidence += highCount;
    totalMediumConfidence += mediumCount;
  }
  
  // Display Supabase database/storage findings
  if (hasSupabaseFindings) {
    if (hasWorkingDirFindings || hasHistoryFindings) {
      console.log(chalk.bold('─'.repeat(60)) + '\n');
    }
    
    console.log(chalk.bold.magenta('🗄️  Database & Storage Findings\n'));
    
    const { display, highCount, mediumCount } = formatSupabaseFindings(supabaseFindings);
    console.log(display);
    totalHighConfidence += highCount;
    totalMediumConfidence += mediumCount;
  }
  
  // Summary
  console.log(chalk.bold('=== Summary ==='));
  if (hasWorkingDirFindings) {
    console.log(`Working directory: ${workingDirFindings.length} finding(s) in ${filesScanned} files`);
  }
  if (hasHistoryFindings) {
    console.log(`Git history: ${historyFindings.length} finding(s)`);
  }
  if (hasSupabaseFindings) {
    console.log(`Database/Storage: ${supabaseFindings.length} finding(s)`);
  }
  console.log(`Total findings: ${workingDirFindings.length + historyFindings.length + supabaseFindings.length}`);
  console.log(chalk.red(`  High severity: ${totalHighConfidence}`));
  console.log(chalk.yellow(`  Medium severity: ${totalMediumConfidence}`));
  
  // Count findings by type across all sources
  const findingsByType = {};
  [...workingDirFindings, ...historyFindings, ...supabaseFindings].forEach(finding => {
    const type = finding.type;
    if (!findingsByType[type]) {
      findingsByType[type] = 0;
    }
    findingsByType[type]++;
  });
  
  console.log('\nFindings by type:');
  for (const [type, count] of Object.entries(findingsByType)) {
    console.log(`  ${type}: ${count}`);
  }

  if (skippedLines) console.log(chalk.gray(skippedLines));

  console.log('');
  
  // Generate and display fix prompts if requested
  if (fixPrompts) {
    const allFindings = [...workingDirFindings, ...historyFindings, ...supabaseFindings];
    const prompts = generateFixPrompts(allFindings);
    displayFixPrompts(prompts);
  }
  
  // Exit code: 1 if any high-confidence findings, 0 otherwise
  return totalHighConfidence > 0 ? 1 : 0;
}

function formatFindings(findings, groupBy = 'file') {
  let output = '';
  let highConfidenceCount = 0;
  let mediumConfidenceCount = 0;
  
  // Group findings by file
  const findingsByFile = {};
  for (const finding of findings) {
    if (!findingsByFile[finding.file]) {
      findingsByFile[finding.file] = [];
    }
    findingsByFile[finding.file].push(finding);
    
    if (finding.confidence === 'high') {
      highConfidenceCount++;
    } else {
      mediumConfidenceCount++;
    }
  }
  
  // Display findings grouped by file
  for (const [file, fileFindings] of Object.entries(findingsByFile)) {
    output += chalk.bold.underline(file) + '\n';
    
    for (const finding of fileFindings) {
      const color = finding.confidence === 'high' ? chalk.red : chalk.yellow;
      const lineRef = chalk.gray(`line ${finding.line}`);
      
      output += color(`  [${finding.type}] ${lineRef}`) + '\n';
      output += color(`  ${finding.redacted}`) + '\n';
    }
    
    output += '\n'; // Empty line between files
  }
  
  return {
    display: output,
    highCount: highConfidenceCount,
    mediumCount: mediumConfidenceCount
  };
}

function formatHistoryFindings(findings) {
  let output = '';
  let highConfidenceCount = 0;
  let mediumConfidenceCount = 0;
  
  // Group findings by commit
  const findingsByCommit = {};
  for (const finding of findings) {
    const key = `${finding.commit} (${finding.date || 'unknown date'})`;
    if (!findingsByCommit[key]) {
      findingsByCommit[key] = {
        findings: [],
        source: finding.source || 'history',
        author: finding.author
      };
    }
    findingsByCommit[key].findings.push(finding);
    
    if (finding.confidence === 'high') {
      highConfidenceCount++;
    } else {
      mediumConfidenceCount++;
    }
  }
  
  // Display all findings
  for (const finding of findings) {
    // Add source label
    let sourceLabel = '';
    if (finding.source === 'reflog') {
      sourceLabel = chalk.yellow(' [reflog - locally recoverable, not on remote]');
    } else if (finding.source === 'orphaned') {
      sourceLabel = chalk.red(' [orphaned/unreachable - may still be locally recoverable]');
    }
    
    output += chalk.bold.magenta(`Commit ${finding.commit} (${finding.date || 'unknown date'})`) + sourceLabel + '\n';
    if (finding.author) {
      output += chalk.gray(`Author: ${finding.author}`) + '\n';
    }
    
    const color = finding.confidence === 'high' ? chalk.red : chalk.yellow;
    output += color(`  [${finding.type}] in ${finding.file}`) + '\n';
    output += color(`  ${finding.redacted}`) + '\n';
    
    output += '\n'; // Empty line between findings
  }
  
  return {
    display: output,
    highCount: highConfidenceCount,
    mediumCount: mediumConfidenceCount
  };
}

function formatSupabaseFindings(findings) {
  let output = '';
  let highSeverityCount = 0;
  let mediumSeverityCount = 0;
  let criticalSeverityCount = 0;
  let infoCount = 0;
  
  for (const finding of findings) {
    let color, icon;
    
    // Determine color and icon based on severity
    if (finding.severity === 'critical') {
      color = chalk.red.bold;
      icon = '🔴🔴';
      criticalSeverityCount++;
    } else if (finding.severity === 'high') {
      color = chalk.red;
      icon = '🔴';
      highSeverityCount++;
    } else if (finding.severity === 'medium') {
      color = chalk.yellow;
      icon = '🟡';
      mediumSeverityCount++;
    } else if (finding.severity === 'info') {
      color = chalk.blue;
      icon = 'ℹ️';
      infoCount++;
    } else {
      color = chalk.gray;
      icon = '⚪';
    }
    
    // Format the finding
    output += color(`${icon} [${finding.type}]`) + '\n';
    
    // Display relevant fields
    if (finding.table) {
      output += color(`   Table: ${finding.table}`) + '\n';
    }
    if (finding.bucket) {
      output += color(`   Bucket: ${finding.bucket}`) + '\n';
    }
    if (finding.policy) {
      output += color(`   Policy: ${finding.policy}`) + '\n';
    }
    if (finding.function) {
      output += color(`   Function: ${finding.function}`) + '\n';
    }
    if (finding.args) {
      output += color(`   Arguments: ${finding.args}`) + '\n';
    }
    
    output += color(`   ${finding.message}`) + '\n';
    
    if (finding.remediation) {
      output += chalk.gray(`   Fix: ${finding.remediation}`) + '\n';
    }
    
    output += '\n';
  }
  
  return {
    display: output,
    highCount: highSeverityCount + criticalSeverityCount,
    mediumCount: mediumSeverityCount
  };
}

module.exports = { formatOutput };
