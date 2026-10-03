const chalk = require('chalk');
const { loadReceipt, isStale } = require('../monitoring/receipt');
const { scanCommand } = require('./scan');

/**
 * Continuous monitoring command
 * @param {Object} options - Command options
 */
async function monitorCommand(options) {
  // Handle graceful shutdown
  process.on('SIGINT', () => {
    console.log('Monitor stopped');
    process.exit(0);
  });

  const targetPath = options.path || process.cwd();
  
  while (true) {
    try {
      // Load previous receipt
      const savedReceipt = loadReceipt(targetPath);
      
      if (options.verbose && savedReceipt) {
        console.log('Loaded previous receipt:', savedReceipt.timestamp);
      }

      // Run full scan
      try {
        await scanCommand({
          path: targetPath,
          supabase: options.supabase,
          supabaseUrl: options.supabaseUrl,
          supabaseKey: options.supabaseKey,
          verbose: options.verbose
        });
      } catch (error) {
        console.warn(chalk.yellow(`⚠️  Scan failed: ${error.message}`));
        if (!options.once) {
          await sleep(options.interval * 60 * 1000);
          continue;
        } else {
          break;
        }
      }

      // Load new receipt after scan
      const newReceipt = loadReceipt(targetPath);

      // Check staleness if we have both receipts
      if (savedReceipt && newReceipt) {
        const { stale, reason } = isStale(newReceipt, savedReceipt);
        if (stale) {
          console.log(chalk.yellow(`⚠️  Receipt stale: ${reason} — re-scan needed`));
        }
      }

      // Exit if running once
      if (options.once) {
        break;
      }

      // Sleep before next iteration
      if (options.verbose) {
        console.log(`Sleeping for ${options.interval} minutes...`);
      }
      await sleep(options.interval * 60 * 1000);
    } catch (error) {
      console.warn(chalk.yellow(`⚠️  Monitor iteration failed: ${error.message}`));
      if (!options.once) {
        await sleep(options.interval * 60 * 1000);
      } else {
        break;
      }
    }
  }
}

/**
 * Sleep helper
 * @param {number} ms - Milliseconds to sleep
 */
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

module.exports = { monitorCommand };
