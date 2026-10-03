const path = require('path');
const { scanDirectory } = require('../scanner/fileWalker');
const { detectSecrets } = require('../scanner/secretDetector');
const { formatOutput } = require('../output/formatter');
const { scanGitHistory } = require('../scanner/gitHistoryScanner');
const { scanRLS } = require('../scanner/supabaseRLS');
const { scanStorage } = require('../scanner/supabaseStorage');
const { scanJWT } = require('../scanner/jwtChecker');
const { runSqliTest } = require('../scanner/sqliChecker');
const { requireAuth } = require('../auth/config');
const { daysSince, formatDate, parseVersion } = require('../scanner/depUtils');
const { readDependencies } = require('../scanner/depScanner');
const { checkOSV } = require('../scanner/osvChecker');
const { checkTyposquat } = require('../scanner/typosquatChecker');
const { checkInstallScripts } = require('../scanner/installScriptChecker');
const { checkRegistry } = require('../scanner/registryChecker');

async function scanCommand(options) {
  // Check authentication unless explicitly skipped via dev mode
  const skipAuth = options.skipAuth && process.env.SHRINE_DEV_SKIP_VALIDATION === '1';
  
  // Default audit deps to true (run by default), skip only if --no-deps is passed
  
  if (!skipAuth) {
    const supabaseUrl = process.env.SHRINE_BACKEND_URL;
    const supabaseAnonKey = process.env.SHRINE_BACKEND_ANON_KEY;
    
    const authResult = await requireAuth(supabaseUrl, supabaseAnonKey);
    if (!authResult) {
      // Auth failed, exit code already set by requireAuth
      return;
    }
  }
  // If SQLi test is requested, run that instead of the normal scan
  if (options.sqli) {
    const exitCode = await runSqliTest(options, options.verbose);
    process.exit(exitCode);
  }

  const targetPath = path.resolve(options.path);
  const verbose = options.verbose;
  const includeTests = options.includeTests;
  const scanHistory = options.history;
  const historyDepth = options.depth || 100;
  const fullHistory = options.fullHistory;
  const deepHistory = options.deepHistory;
  const useEntropy = options.entropy;
  const useAST = options.ast; // Will be undefined (truthy enough) or explicitly false with --no-ast
  const respectGitignore = options.respectGitignore || false; // Opt-in: default scans everything
  // NOTE: --full is a no-op (full coverage is the default); accepted for compat.
  const scanSupabase = options.supabase;
  const supabaseUrl = options.supabaseUrl || process.env.SUPABASE_URL;
  const supabaseKey = options.supabaseKey || process.env.SUPABASE_SERVICE_ROLE_KEY;
  const auditDeps = options.deps !== false;
  const supabaseAnonKey = options.supabaseAnonKey || process.env.SUPABASE_ANON_KEY;
  const allowWriteTest = options.allowWriteTest || false;

  if (verbose) {
    console.log(`Scanning directory: ${targetPath}`);
    if (useEntropy) {
      console.log('Entropy-based detection enabled');
    }
    if (useAST === false) {
      console.log('AST parsing disabled - using regex-only mode');
    }
    if (scanSupabase) {
      console.log('Supabase database/storage scanning enabled');
    }
    if (auditDeps) {
      console.log('Dependency audit enabled');
    } else {
      console.log('Dependency audit skipped (--no-deps)');
    }
  }

  try {
    let workingDirFindings = [];
    let historyFindings = [];
    let supabaseFindings = [];
    let filesScanned = 0;

    // Scan working directory (full coverage by default)
    const { files, skipped } = await scanDirectory(targetPath, verbose, respectGitignore);
    filesScanned = files.length;

    if (verbose) {
      console.log(`Found ${files.length} files to scan`);
    }

    // Scan each file for secrets
    for (const file of files) {
      const findings = await detectSecrets(file, targetPath, { verbose, includeTests, useEntropy, useAST });
      if (findings.length > 0) {
        workingDirFindings.push(...findings);
      }
    }

    // Scan git history if requested
    if (scanHistory) {
      const depth = fullHistory ? null : historyDepth;
      historyFindings = await scanGitHistory(targetPath, { verbose, depth, includeTests, useEntropy, deepHistory });
    }

    // Scan Supabase if requested
    if (scanSupabase) {
      if (!supabaseUrl || !supabaseKey) {
        console.error('\nSupabase scan requested but credentials missing.');
        console.error('Please set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY environment variables,');
        console.error('or use --supabase-url and --supabase-key flags.\n');
      } else {
        try {
          if (verbose) {
            console.log(`\nConnecting to Supabase: ${supabaseUrl}`);
          }

          // Scan RLS configuration
          const rlsFindings = await scanRLS(supabaseUrl, supabaseKey, { 
            verbose, 
            anonKey: supabaseAnonKey, 
            allowWriteTest 
          });
          supabaseFindings.push(...rlsFindings);

          // Scan storage buckets
          const storageFindings = await scanStorage(supabaseUrl, supabaseKey, { verbose });
          supabaseFindings.push(...storageFindings);

          if (verbose) {
            console.log(`Supabase scan complete: ${supabaseFindings.length} finding(s)`);
          }
        } catch (error) {
          console.error(`\nSupabase scan failed: ${error.message}`);
          if (verbose) {
            console.error(error.stack);
          }
          console.error('Continuing with other scans...\n');
        }
      }
    }

    // Scan for JWT tokens (always runs as part of normal scan)
    const jwtFindings = await scanJWT({
      path: targetPath,
      verbose,
      includeTests,
      respectGitignore
    });
    workingDirFindings.push(...jwtFindings);

    // Run dependency audit if not skipped
    if (auditDeps) {
      if (verbose) {
        console.log('Running dependency audit...');
      }
      
      let offlineChecks = [];
      let networkError = false;
      
      try {
        // Read dependencies from package files
        const dependencies = await readDependencies(targetPath);
        if (verbose) {
          console.log(`Found ${Object.keys(dependencies).length} dependencies to audit`);
        }
        
        // Check registry for nonexistent/new packages
        try {
          const registryFindings = await checkRegistry(dependencies);
          if (verbose) {
            console.log(`Registry check found ${registryFindings.length} issues`);
          }
          workingDirFindings.push(...registryFindings);
        } catch (error) {
          if (!networkError) {
            offlineChecks.push('registry (nonexistent/new packages)');
            networkError = true;
          }
        }
        
        // Check for OSV vulnerabilities
        try {
          const osvFindings = await checkOSV(dependencies);
          if (verbose) {
            console.log(`OSV check found ${osvFindings.length} vulnerabilities`);
          }
          workingDirFindings.push(...osvFindings);
        } catch (error) {
          if (!networkError) {
            offlineChecks.push('OSV (vulnerabilities)');
            networkError = true;
          }
        }
        
        // Check for typosquatting risks
        try {
          const typosquatFindings = await checkTyposquat(dependencies);
          if (verbose) {
            console.log(`Typosquat check found ${typosquatFindings.length} risks`);
          }
          workingDirFindings.push(...typosquatFindings);
        } catch (error) {
          if (!networkError) {
            offlineChecks.push('typosquat');
            networkError = true;
          }
        }
        
        // Check for dangerous install scripts
        try {
          const scriptFindings = await checkInstallScripts(targetPath, dependencies);
          if (verbose) {
            console.log(`Install script check found ${scriptFindings.length} scripts`);
          }
          workingDirFindings.push(...scriptFindings);
        } catch (error) {
          if (!networkError) {
            offlineChecks.push('install scripts');
            networkError = true;
          }
        }
        
        // Single offline warning if any checks were skipped
        if (offlineChecks.length > 0) {
          console.warn(`Offline/skipped dependency checks: ${offlineChecks.join(', ')}`);
        }
      } catch (error) {
        console.error(`Dependency audit failed: ${error.message}`);
        if (verbose) {
          console.error(error.stack);
        }
      }
    }

    // Optional Codestral triage: classify each finding as important/noise
    if (options.triage) {
      const apiKey = options.triageKey || process.env.MISTRAL_API_KEY;
      if (!apiKey) {
        console.log('\nCodestral triage requested but no API key found.');
        console.log('Set MISTRAL_API_KEY or use --triage-key <key>. Showing all findings.\n');
      } else {
        const { triageFindings } = require('../triage/codestral');
        console.log('\nTriaging findings with Codestral...');
        await triageFindings([...workingDirFindings, ...historyFindings], {
          apiKey,
          scanRoot: targetPath
        });
      }
    }

    // Hide noise unless --all
    if (options.triage && !options.all) {
      const hiddenWd = workingDirFindings.filter(f => f.triage === 'noise').length;
      const hiddenHist = historyFindings.filter(f => f.triage === 'noise').length;
      workingDirFindings = workingDirFindings.filter(f => f.triage !== 'noise');
      historyFindings = historyFindings.filter(f => f.triage !== 'noise');
      if (hiddenWd + hiddenHist > 0) {
        console.log(`\nCodestral triage: ${hiddenWd + hiddenHist} noise finding(s) hidden (use --all to show)\n`);
      }
    }

    // Format and display output
    const exitCode = formatOutput({
      workingDir: workingDirFindings,
      history: historyFindings,
      supabase: supabaseFindings,
      filesScanned,
      skipped,
      fixPrompts: options.fixPrompts
    });
    process.exit(exitCode);
  } catch (error) {
    console.error(`Error during scan: ${error.message}`);
    process.exit(1);
  }
}

module.exports = { scanCommand };
