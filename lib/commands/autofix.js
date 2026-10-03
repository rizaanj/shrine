const path = require('path');
const readline = require('readline');
const { scanDirectory } = require('../scanner/fileWalker');
const { detectSecrets } = require('../scanner/secretDetector');
const { scanGitHistory } = require('../scanner/gitHistoryScanner');
const { scanRLS } = require('../scanner/supabaseRLS');
const { scanStorage } = require('../scanner/supabaseStorage');
const { scanJWT } = require('../scanner/jwtChecker');
const { generateFixPrompts } = require('../output/fixPromptGenerator');
const { requireAuth } = require('../auth/config');
const chalk = require('chalk');

/**
 * Interactive review command - shows fix prompts for approval (does not edit files)
 */
async function autofixCommand(options) {
  // Check authentication unless explicitly skipped
  const skipAuth = options.skipAuth && process.env.SHRINE_DEV_SKIP_VALIDATION === '1';
  
  if (!skipAuth) {
    const supabaseUrl = process.env.SHRINE_BACKEND_URL;
    const supabaseAnonKey = process.env.SHRINE_BACKEND_ANON_KEY;
    
    const authResult = await requireAuth(supabaseUrl, supabaseAnonKey);
    if (!authResult) {
      return;
    }
  }

  console.log(chalk.bold.cyan('\n🔍 Shrine Review - Comprehensive Security Scan\n'));
  console.log(chalk.gray('Scanning: working directory, git history, and Supabase (if configured)\n'));

  const targetPath = path.resolve(options.path || process.cwd());
  const verbose = options.verbose || false;
  const includeTests = options.includeTests || false;
  const useEntropy = options.entropy || false;
  const useAST = options.ast !== false;
  const supabaseUrl = options.supabaseUrl || process.env.SUPABASE_URL;
  const supabaseKey = options.supabaseKey || process.env.SUPABASE_SERVICE_ROLE_KEY;
  const supabaseAnonKey = options.supabaseAnonKey || process.env.SUPABASE_ANON_KEY;
  const allowWriteTest = options.allowWriteTest || false;

  try {
    let allFindings = [];

    // 1. Scan working directory
    if (verbose) console.log(chalk.gray('Scanning working directory...'));
    const files = await scanDirectory(targetPath, verbose);
    for (const file of files) {
      const findings = await detectSecrets(file, targetPath, { verbose, includeTests, useEntropy, useAST });
      allFindings.push(...findings);
    }

    // 2. Scan JWT tokens
    const jwtFindings = await scanJWT({ path: targetPath, verbose, includeTests });
    allFindings.push(...jwtFindings);

    // 3. Scan git history (always enabled for auto-fix)
    if (verbose) console.log(chalk.gray('Scanning git history...'));
    try {
      const historyFindings = await scanGitHistory(targetPath, { 
        verbose, 
        depth: 100, 
        includeTests, 
        useEntropy, 
        deepHistory: false 
      });
      allFindings.push(...historyFindings);
    } catch (error) {
      if (verbose) console.log(chalk.yellow(`Git history scan skipped: ${error.message}`));
    }

    // 4. Scan Supabase (if configured)
    if (supabaseUrl && supabaseKey) {
      if (verbose) console.log(chalk.gray('Scanning Supabase RLS and storage...'));
      try {
        const rlsFindings = await scanRLS(supabaseUrl, supabaseKey, { 
          verbose, 
          anonKey: supabaseAnonKey, 
          allowWriteTest 
        });
        allFindings.push(...rlsFindings);

        const storageFindings = await scanStorage(supabaseUrl, supabaseKey, { verbose });
        allFindings.push(...storageFindings);
      } catch (error) {
        console.log(chalk.yellow(`\nSupabase scan failed: ${error.message}`));
      }
    }

    // Generate fix prompts
    const fixPrompts = generateFixPrompts(allFindings);

    if (fixPrompts.length === 0) {
      console.log(chalk.green('\n✓ No security issues found!\n'));
      process.exit(0);
    }

    console.log(chalk.bold.yellow(`\n⚠️  Found ${allFindings.length} security issue(s) across ${fixPrompts.length} type(s)\n`));

    // Interactive approval for each fix
    let appliedCount = 0;
    let skippedCount = 0;

    for (let i = 0; i < fixPrompts.length; i++) {
      const prompt = fixPrompts[i];
      const severityColor = prompt.severity === 'high' ? chalk.red : chalk.yellow;
      
      console.log(chalk.gray('─'.repeat(80)));
      console.log(severityColor.bold(`\n[${i + 1}/${fixPrompts.length}] ${prompt.type} (${prompt.severity} severity)`));
      console.log(chalk.gray(`Occurrences: ${prompt.count}\n`));
      console.log(prompt.fullPrompt);
      console.log('\n' + chalk.gray('─'.repeat(80)));

      const answer = await askYesNo(`\nMark as reviewed? (Y/n)`);
      
      if (answer) {
        console.log(chalk.green('✓ Marked as reviewed - Copy the prompt above to implement this fix\n'));
        appliedCount++;
      } else {
        console.log(chalk.yellow('⊘ Skipped\n'));
        skippedCount++;
      }
    }

    console.log(chalk.bold.cyan('\n📊 Review Summary'));
    console.log(chalk.gray('─'.repeat(80)));
    console.log(`Total issues found: ${chalk.yellow(allFindings.length)}`);
    console.log(`Fix prompts reviewed: ${chalk.cyan(fixPrompts.length)}`);
    console.log(`Marked for action: ${chalk.green(appliedCount)}`);
    console.log(`Skipped: ${chalk.yellow(skippedCount)}`);
    console.log(chalk.gray('─'.repeat(80)));
    console.log(chalk.gray('\nNote: No files were modified. Copy the reviewed prompts to implement fixes.\n'));

    process.exit(allFindings.length > 0 ? 1 : 0);
  } catch (error) {
    console.error(chalk.red(`\nError during auto-fix: ${error.message}`));
    if (verbose) console.error(error.stack);
    process.exit(1);
  }
}

/**
 * Ask a yes/no question and return boolean
 */
function askYesNo(question) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  return new Promise((resolve) => {
    rl.question(chalk.cyan(question) + ' ', (answer) => {
      rl.close();
      const normalized = answer.toLowerCase().trim();
      resolve(normalized === 'y' || normalized === 'yes' || normalized === '');
    });
  });
}

module.exports = { autofixCommand };
