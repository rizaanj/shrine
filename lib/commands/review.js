const path = require('path');
const readline = require('readline');
const chalk = require('chalk');
const { scanDirectory } = require('../scanner/fileWalker');
const { detectSecrets } = require('../scanner/secretDetector');
const { scanGitHistory } = require('../scanner/gitHistoryScanner');
const { scanRLS } = require('../scanner/supabaseRLS');
const { scanStorage } = require('../scanner/supabaseStorage');
const { scanJWT } = require('../scanner/jwtChecker');
const { scanDirectoryForPatterns } = require('../scanner/codePatternScanner');
const { readDependencies } = require('../scanner/depScanner');
const { checkOSV } = require('../scanner/osvChecker');
const { checkTyposquat } = require('../scanner/typosquatChecker');
const { checkInstallScripts } = require('../scanner/installScriptChecker');
const { generateFix, applyFix } = require('../autofix/fixer');

/**
 * Generate unified diff preview
 */
function generateDiff(original, patched) {
  const origLines = original.split('\n');
  const patchLines = patched.split('\n');
  
  let diff = [];
  let lineNum = 1;
  
  // Simple diff: show removed and added lines
  for (let i = 0; i < Math.max(origLines.length, patchLines.length); i++) {
    if (i < origLines.length && origLines[i] !== (patchLines[i] || '')) {
      diff.push(chalk.red(`- ${origLines[i]}`));
    }
    if (i < patchLines.length && patchLines[i] !== (origLines[i] || '')) {
      diff.push(chalk.green(`+ ${patchLines[i]}`));
    }
    lineNum++;
    
    // Limit to 10 lines context
    if (diff.length >= 10) {
      diff.push('  ...');
      break;
    }
  }
  
  return diff.join('\n');
}

/**
 * Ask user for confirmation
 */
function askConfirmation(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });
    
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim().toLowerCase());
    });
  });
}

/**
 * Review command: scan and interactively apply fixes
 */
async function reviewCommand(options) {
  const targetPath = path.resolve(options.path);
  const verbose = options.verbose;
  const autoApply = options.apply || false;
  const includeTests = options.includeTests || false;
  const useEntropy = options.entropy || false;
  const useAST = options.ast !== false;
  const respectGitignore = options.respectGitignore || false;
  const scanSupabase = options.supabaseUrl && options.supabaseKey;
  const supabaseUrl = options.supabaseUrl || process.env.SUPABASE_URL;
  const supabaseKey = options.supabaseKey || process.env.SUPABASE_SERVICE_ROLE_KEY;
  const supabaseAnonKey = options.supabaseAnonKey || process.env.SUPABASE_ANON_KEY;
  const allowWriteTest = options.allowWriteTest || false;

  if (verbose) {
    console.log(chalk.cyan(`Scanning directory: ${targetPath}`));
  }

  try {
    // Run full scan
    let allFindings = [];
    let filesScanned = 0;

    // Scan working directory
    const { files } = await scanDirectory(targetPath, verbose, respectGitignore);
    filesScanned = files.length;

    if (verbose) {
      console.log(`Found ${files.length} files to scan`);
    }

    // Scan each file for secrets
    for (const file of files) {
      const findings = await detectSecrets(file, targetPath, { verbose, includeTests, useEntropy, useAST });
      if (findings.length > 0) {
        allFindings.push(...findings);
      }
    }

    // Scan JWT tokens
    const jwtFindings = await scanJWT({
      path: targetPath,
      verbose,
      includeTests,
      useEntropy
    });
    allFindings.push(...jwtFindings);

    // Code pattern scan (XSS, injection, etc.)
    const codeFindings = await scanDirectoryForPatterns(targetPath, { verbose, useAST });
    allFindings.push(...codeFindings);

    // Dependency audit
    const packageManifests = files.filter(f => 
      f.endsWith('package.json') || 
      f.endsWith('package-lock.json') || 
      f.endsWith('yarn.lock') ||
      f.endsWith('pnpm-lock.yaml')
    );

    for (const manifest of packageManifests) {
      try {
        const deps = await readDependencies(manifest);
        
        // OSV vulnerabilities
        const osvFindings = await checkOSV(deps, manifest, verbose);
        allFindings.push(...osvFindings);
        
        // Typosquatting
        const typoFindings = await checkTyposquat(deps, manifest, verbose);
        allFindings.push(...typoFindings);
        
        // Install scripts
        const scriptFindings = await checkInstallScripts(deps, manifest, verbose);
        allFindings.push(...scriptFindings);
      } catch (err) {
        if (verbose) {
          console.warn(`Dependency scan failed for ${manifest}: ${err.message}`);
        }
      }
    }

    // Supabase scan if requested
    if (scanSupabase && supabaseUrl && supabaseKey) {
      try {
        if (verbose) {
          console.log(chalk.cyan(`\nConnecting to Supabase: ${supabaseUrl}`));
        }

        const rlsFindings = await scanRLS(supabaseUrl, supabaseKey, { 
          verbose, 
          anonKey: supabaseAnonKey, 
          allowWriteTest 
        });
        allFindings.push(...rlsFindings);

        const storageFindings = await scanStorage(supabaseUrl, supabaseKey, { verbose });
        allFindings.push(...storageFindings);
      } catch (error) {
        console.error(chalk.red(`\nSupabase scan failed: ${error.message}`));
      }
    }

    if (verbose) {
      console.log(chalk.cyan(`\nTotal findings: ${allFindings.length}`));
    }

    // Filter fixable findings
    const fixableFindings = [];
    for (const finding of allFindings) {
      const fix = generateFix(finding);
      if (fix !== null) {
        fixableFindings.push({ finding, fix });
      }
    }

    console.log(chalk.cyan(`\nFixable findings: ${fixableFindings.length}`));

    if (fixableFindings.length === 0) {
      console.log(chalk.green('No auto-fixable issues found.'));
      process.exit(0);
      return;
    }

    let appliedCount = 0;
    let skippedCount = 0;
    let skipAll = false;

    // Interactive review
    for (const { finding, fix } of fixableFindings) {
      if (skipAll) {
        skippedCount++;
        continue;
      }

      console.log('\n' + chalk.cyan('─'.repeat(60)));
      console.log(chalk.cyan(`${finding.type} in ${finding.file}:${finding.line}`));
      console.log(chalk.yellow(`Description: ${fix.description}`));
      
      if (fix.fixed) {
        console.log(chalk.white('\nDiff:'));
        console.log(generateDiff(fix.original, fix.patched));
      } else {
        // SQL or non-file fix
        console.log(chalk.white('\nAction required:'));
        console.log(chalk.yellow(fix.description));
      }

      if (autoApply) {
        if (fix.fixed) {
          const result = applyFix(finding, fix);
          if (result.applied) {
            console.log(chalk.green('✓ Applied'));
            appliedCount++;
          } else {
            console.log(chalk.red(`✗ Failed: ${result.error}`));
            skippedCount++;
          }
        } else {
          console.log(chalk.yellow('⚠ Manual action required'));
          skippedCount++;
        }
      } else {
        // Interactive mode
        const answer = await askConfirmation('\nApply this fix? (y/n/skip all): ');
        
        if (answer === 'skip all' || answer === 's') {
          skipAll = true;
          skippedCount++;
          console.log(chalk.yellow('Skipping all remaining fixes'));
        } else if (answer === 'y' || answer === 'yes') {
          if (fix.fixed) {
            const result = applyFix(finding, fix);
            if (result.applied) {
              console.log(chalk.green('✓ Applied'));
              appliedCount++;
            } else {
              console.log(chalk.red(`✗ Failed: ${result.error}`));
              skippedCount++;
            }
          } else {
            console.log(chalk.yellow('⚠ Manual action required - marked as skipped'));
            skippedCount++;
          }
        } else {
          console.log(chalk.yellow('Skipped'));
          skippedCount++;
        }
      }
    }

    // Summary
    console.log('\n' + chalk.cyan('─'.repeat(60)));
    console.log(chalk.white(`${appliedCount} fixes applied, ${skippedCount} skipped.`));
    
    process.exit(0);
  } catch (error) {
    console.error(chalk.red(`Error during review: ${error.message}`));
    if (verbose) {
      console.error(error.stack);
    }
    process.exit(1);
  }
}

module.exports = { reviewCommand };
