const fs = require('fs');

/**
 * Check for potentially dangerous install scripts in package.json
 * Only check preinstall, install, and postinstall (not prepare)
 */
async function checkInstallScripts(targetPath) {
  const packagePath = `${targetPath}/package.json`;
  const findings = [];
  
  try {
    const packageData = await fs.promises.readFile(packagePath, 'utf-8');
    const pkg = JSON.parse(packageData);
    
    // Check for dangerous scripts (preinstall, install, postinstall only)
    const dangerousScripts = ['preinstall', 'install', 'postinstall'];
    
    for (const script of dangerousScripts) {
      if (pkg.scripts && pkg.scripts[script]) {
      findings.push({
        type: 'Install Script',
        script: script,
        command: pkg.scripts[script],
        severity: 'medium',
        summary: `Dangerous install script detected: ${script}`,
        details: `Command: ${pkg.scripts[script]}`,
        package: pkg.name || 'unknown',
        file: packagePath,
        line: 0
      });
      }
    }
  } catch (error) {
    // File doesn't exist or can't be read - that's fine
  }
  
  return findings;
}

module.exports = { checkInstallScripts };