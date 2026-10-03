const { scanPR } = require('../ci/prScan');

/**
 * PR scan command
 * @param {string|number} prNumber - PR/MR number
 * @param {Object} options - Command options
 */
async function prCommand(prNumber, options) {
  try {
    const result = await scanPR({
      prNumber,
      provider: options.provider,
      verbose: options.verbose,
      targetPath: options.path
    });

    console.log(
      `Scan complete: ${result.findings.total} findings, ${result.findings.high} high. ${
        result.blockMerge ? 'Blocked' : 'Passed'
      }`
    );

    if (result.blockMerge) {
      process.exit(1);
    } else {
      process.exit(0);
    }
  } catch (error) {
    console.error(`PR scan failed: ${error.message}`);
    process.exit(1);
  }
}

module.exports = { prCommand };
