const fs = require('fs');
const { getPackageMetadata } = require('./registryChecker');
const { daysSince } = require('./depUtils');

/**
 * Check for potentially dangerous install scripts in package.json
 * Only flag packages under 30 days old with preinstall, install, or postinstall scripts
 */
async function checkInstallScripts(targetPath, dependencies) {
  const packagePath = `${targetPath}/package.json`;
  const findings = [];
  
  try {
    const packageData = await fs.promises.readFile(packagePath, 'utf-8');
    const pkg = JSON.parse(packageData);
    
    // Check for dangerous scripts (preinstall, install, postinstall only)
    const dangerousScripts = ['preinstall', 'install', 'postinstall'];
    const scriptsToReport = [];
    
    for (const script of dangerousScripts) {
      if (pkg.scripts && pkg.scripts[script]) {
        scriptsToReport.push(script);
      }
    }
    
    // Only report if package has dangerous scripts
    if (scriptsToReport.length === 0) {
      return findings;
    }
    
    // Check each dependency for age
    for (const [name, dep] of Object.entries(dependencies)) {
      const metadata = await getPackageMetadata(name);
      
      if (!metadata || !metadata.created) {
        continue;
      }
      
      const createdDaysAgo = daysSince(metadata.created);
      
      // Only flag if package is under 30 days old and has install scripts
      if (createdDaysAgo < 30) {
        findings.push({
          type: 'Install Script',
          package: name,
          version: dep.version,
          severity: 'medium',
          confidence: 'medium',
          redacted: name,
          summary: `Package "${name}" (${createdDaysAgo} days old) has install scripts: ${scriptsToReport.join(', ')}`,
          details: `Scripts: ${scriptsToReport.map(s => `${s}: ${pkg.scripts[s]}`).join('; ')}`,
          file: packagePath,
          line: 0,
          fixPrompt: `Review install scripts for "${name}" before installation. Consider using --ignore-scripts flag.`
        });
      }
    }
  } catch (error) {
    // File doesn't exist or can't be read - that's fine
  }
  
  return findings;
}

module.exports = { checkInstallScripts };
