const { spawn } = require('child_process');
const { exec } = require('child_process');
const path = require('path');

/**
 * Check if sqlmap is installed and return the command to use
 * @returns {Promise<string|null>} The sqlmap command to use, or null if not found
 */
function findSqlmapCommand() {
  return new Promise((resolve) => {
    // Debug: print the PATH that Node sees
    console.log('[DEBUG] Node process PATH:');
    console.log(process.env.PATH);
    console.log('[DEBUG] ========================');
    
    // Use shell: true to ensure proper command resolution on Windows
    const execOptions = { 
      timeout: 5000,
      shell: true 
    };
    
    // Try 'sqlmap' first (common on Linux/Mac with pip install)
    exec('sqlmap --version', execOptions, (error, stdout, stderr) => {
      if (!error && stdout) {
        console.log('[DEBUG] sqlmap command found via direct call');
        console.log('[DEBUG] sqlmap version output:', stdout.trim());
        resolve('sqlmap');
        return;
      }
      
      console.log('[DEBUG] Direct sqlmap call failed:', error?.message || 'no output');
      
      // Try using 'where' command on Windows to locate sqlmap
      exec('where sqlmap', execOptions, (error2, stdout2, stderr2) => {
        if (!error2 && stdout2) {
          const sqlmapPath = stdout2.trim().split('\n')[0]; // Get first result
          console.log('[DEBUG] sqlmap found via where command:', sqlmapPath);
          resolve('sqlmap'); // Use 'sqlmap' since it's in PATH
          return;
        }
        
        console.log('[DEBUG] where sqlmap failed:', error2?.message || 'not found');
        
        // Try 'which' on Unix/Linux
        exec('which sqlmap', execOptions, (errorWhich, stdoutWhich, stderrWhich) => {
          if (!errorWhich && stdoutWhich) {
            console.log('[DEBUG] sqlmap found via which command:', stdoutWhich.trim());
            resolve('sqlmap');
            return;
          }
          
          // Try 'sqlmap.py' (common on Windows when installed manually)
          exec('sqlmap.py --version', execOptions, (error3, stdout3, stderr3) => {
            if (!error3 && stdout3) {
              console.log('[DEBUG] sqlmap.py command found');
              resolve('sqlmap.py');
              return;
            }
            
            console.log('[DEBUG] sqlmap.py failed:', error3?.message || 'no output');
            
            // Try 'python -m sqlmap --version' (Python module invocation)
            exec('python -m sqlmap --version', execOptions, (error4, stdout4, stderr4) => {
              if (!error4 && stdout4) {
                console.log('[DEBUG] sqlmap via python -m found');
                resolve('python -m sqlmap');
                return;
              }
              
              console.log('[DEBUG] python -m sqlmap failed:', error4?.message || 'no output');
              
              // Last resort: check if sqlmap is installed via pip
              exec('python -m pip show sqlmap', execOptions, (error5, stdout5, stderr5) => {
                if (!error5 && stdout5 && stdout5.includes('Name: sqlmap')) {
                  console.log('[DEBUG] sqlmap package found via pip show');
                  console.log('[DEBUG] Using python -m sqlmap as fallback');
                  resolve('python -m sqlmap');
                  return;
                }
                
                console.log('[DEBUG] pip show sqlmap failed:', error5?.message || 'not found');
                console.log('[DEBUG] sqlmap not found - tried all methods');
                resolve(null);
              });
            });
          });
        });
      });
    });
  });
}

/**
 * Ask for confirmation from the user
 * @param {string} question The question to ask
 * @returns {Promise<boolean>} true if user confirmed, false otherwise
 */
function askForConfirmation(question) {
  const readline = require('readline').createInterface({
    input: process.stdin,
    output: process.stdout
  });

  return new Promise((resolve) => {
    readline.question(question + ' (y/N) ', (answer) => {
      readline.close();
      resolve(answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes');
    });
  });
}

/**
 * Run sqlmap against the target URL and parse the results
 * @param {string} sqlmapCommand The sqlmap command to use (e.g., 'sqlmap', 'sqlmap.py', 'python -m sqlmap')
 * @param {string} url The target URL to test
 * @param {number} level The level of tests to perform (1-5)
 * @param {number} risk The risk of tests to perform (1-3)
 * @param {boolean} verbose Whether to show verbose output
 * @returns {Promise<Array>} Array of findings in shrine format
 */
async function runSqlmapScan(sqlmapCommand, url, level, risk, verbose) {
  return new Promise((resolve, reject) => {
    console.log(`[DEBUG] Running sqlmap with command: ${sqlmapCommand}`);
    
    // Parse the command - it might be multi-word like "python -m sqlmap"
    const commandParts = sqlmapCommand.split(' ');
    const mainCommand = commandParts[0];
    const mainArgs = commandParts.slice(1);
    
    // Build the full arguments array
    const args = [
      ...mainArgs,
      '-u', url,
      '--batch',
      `--level=${level}`,
      `--risk=${risk}`,
      '--output-dir=' + path.join(__dirname, '..', '..', 'sqlmap_output')
    ];
    
    console.log(`[DEBUG] Spawning: ${mainCommand} ${args.join(' ')}`);
    
    const sqlmap = spawn(mainCommand, args, {
      shell: true,
      stdio: ['ignore', 'pipe', 'pipe'] // stdin ignored, stdout/stderr piped
    });

    let stdoutData = '';
    let stderrData = '';

    // Always stream output to console in real-time
    sqlmap.stdout.on('data', (data) => {
      const text = data.toString();
      stdoutData += text;
      process.stdout.write(text);
    });

    sqlmap.stderr.on('data', (data) => {
      const text = data.toString();
      stderrData += text;
      if (verbose) {
        process.stderr.write(text);
      }
    });

    sqlmap.on('error', (err) => {
      console.error('[DEBUG] spawn error:', err.message);
      reject(new Error(`Failed to spawn sqlmap: ${err.message}`));
    });

    sqlmap.on('close', (code) => {
      console.log(`[DEBUG] sqlmap process exited with code ${code}`);
      
      // sqlmap exit codes:
      // 0 = completed successfully (no vulnerabilities found)
      // 1 = user quit or error
      // We'll parse output regardless of exit code
      
      // Parse the output to extract findings
      const findings = parseSqlmapOutput(stdoutData, stderrData, url);
      resolve(findings);
    });
  });
}

/**
 * Parse sqlmap output to extract findings
 * @param {string} stdout The stdout from sqlmap
 * @param {string} stderr The stderr from sqlmap
 * @param {string} url The target URL
 * @returns {Array} Array of findings in shrine format
 */
function parseSqlmapOutput(stdout, stderr, url) {
  const findings = [];

  // We'll look for common indicators of SQL injection in sqlmap output
  // This is a simplified parser; in reality, sqlmap output can be complex
  const lines = stdout.split('\n');

  let currentVuln = null;

  for (const line of lines) {
    // Look for lines that indicate a parameter is vulnerable
    if (line.includes('Parameter:') && line.includes('is vulnerable')) {
      // Example: "Parameter: id (GET) is vulnerable. Do you want to keep testing the others? [y/N]"
      // We'll extract the parameter and the type
      const match = line.match(/Parameter:\s*(.+?)\s*\((.+?)\)\s+is vulnerable/);
      if (match) {
        const param = match[1];
        const type = match[2]; // GET, POST, etc.

        // Look for the payload or the technique in the following lines
        // We'll set a placeholder and then look for more details
        currentVuln = {
          param,
          type,
          technique: '',
          payload: '',
          dbms: ''
        };
      }
    }

    // Look for technique
    if (currentVuln && line.includes('Technique:')) {
      const match = line.match(/Technique:\s*(.+)/);
      if (match) {
        currentVuln.technique = match[1];
      }
    }

    // Look for payload
    if (currentVuln && line.includes('Payload:')) {
      const match = line.match(/Payload:\s*(.+)/);
      if (match) {
        currentVuln.payload = match[1];
      }
    }

    // Look for DBMS
    if (currentVuln && line.includes('DBMS:')) {
      const match = line.match(/DBMS:\s*(.+)/);
      if (match) {
        currentVuln.dbms = match[1];
      }
    }

    // When we have enough information, create a finding
    if (currentVuln && currentVuln.param && currentVuln.technique && currentVuln.payload) {
      // Determine severity based on technique and DBMS
      // This is a simplified mapping
      let severity = 'medium';
      if (currentVuln.technique.includes('UNION') || currentVuln.technique.includes('STACKED')) {
        severity = 'high';
      }
      if (currentVuln.technique.includes('BLIND') || currentVuln.technique.includes('TIME')) {
        severity = 'medium';
      }

      findings.push({
        type: 'SQL Injection',
        file: url, // We'll use the URL as the file
        line: 0,   // Not applicable
        message: `SQL injection found in parameter '${currentVuln.param}' (${currentVuln.type}) using ${currentVuln.technique} technique.`,
        confidence: 'high', // We are confident because sqlmap confirmed it
        severity: severity,
        redacted: `Payload: ${currentVuln.payload}`,
        remediation: `Use parameterized queries or prepared statements. Implement input validation and output encoding.`
      });

      // Reset for next vulnerability
      currentVuln = null;
    }
  }

  // If we found vulnerabilities, we might also want to add a summary finding
  // But for now, we'll just return the individual findings

  return findings;
}

/**
 * Main function to run the SQLi test
 * @param {Object} options The command line options
 * @param {boolean} verbose Whether to show verbose output
 * @returns {Promise<number>} Exit code (0 for no high severity findings, 1 for high severity findings)
 */
async function runSqliTest(options, verbose) {
  console.log(`\n[+] Starting SQL injection test on ${options.sqli}`);
  console.log('[DEBUG] About to check sqlmap installation...');

  // Check if sqlmap is installed and get the command to use
  const sqlmapCommand = await findSqlmapCommand();
  console.log(`[DEBUG] sqlmap command result: ${sqlmapCommand}`);
  
  if (!sqlmapCommand) {
    console.error('\n[!] Error: sqlmap is not installed or not in PATH.');
    console.error('    Please install sqlmap:');
    console.error('    - Linux/Mac: pip install sqlmap');
    console.error('    - Windows: pip install sqlmap OR download from http://sqlmap.org');
    console.error('    - Verify installation: sqlmap --version\n');
    return 1;
  }

  // Ask for confirmation
  console.log('[DEBUG] About to ask for confirmation...');
  const confirmed = await askForConfirmation('[!] WARNING: SQL injection testing can be harmful and is only authorized on systems you own or have explicit permission to test. Continue?');
  console.log(`[DEBUG] Confirmation result: ${confirmed}`);
  
  if (!confirmed) {
    console.log('\n[+] SQL injection test aborted by user.\n');
    return 0;
  }

  console.log('[DEBUG] About to run sqlmap scan...');
  try {
    // Ensure level and risk have valid defaults
    const level = options.sqliLevel || 1;
    const risk = options.sqliRisk || 1;
    console.log(`[DEBUG] SQLi test parameters - level: ${level}, risk: ${risk}`);
    
    // Run sqlmap
    const findings = await runSqlmapScan(sqlmapCommand, options.sqli, level, risk, verbose);
    console.log(`[DEBUG] sqlmap scan completed with ${findings.length} findings`);

    // Format and display the output
    // We'll reuse the existing output formatter but we need to adapt it for our findings
    // For simplicity, we'll create a temporary object that matches the expected format of formatOutput
    const results = {
      workingDir: findings,
      history: [],
      supabase: [],
      filesScanned: 0 // We didn't scan files, but we need to provide this
    };

    const exitCode = require('../output/formatter').formatOutput(results);
    return exitCode;
  } catch (error) {
    console.error(`\n[!] Error during SQL injection test: ${error.message}`);
    if (verbose) {
      console.error(error.stack);
    }
    console.error('\n');
    return 1;
  }
}

module.exports = {
  runSqliTest
};