const fs = require('fs');
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
const { getPackageMetadata } = require('./registryChecker');
const { daysSince } = require('./depUtils');

const MOCK_REGISTRY = process.env.SHRINE_MOCK_REGISTRY === '1' ? {
  'brand-new-package-under-30-days': {
    scripts: {
      preinstall: 'node malicious.js',
      install: 'echo installing',
      postinstall: 'node setup.js'
    }
  }
} : null;

/**
 * Fetch package manifest for a specific version from npm registry
 */
async function getPackageManifest(name, version) {
  // Check mock registry first for testing
  if (MOCK_REGISTRY && MOCK_REGISTRY[name] && MOCK_REGISTRY[name].scripts) {
    return { scripts: MOCK_REGISTRY[name].scripts };
  }
  
  try {
    const response = await fetch(`https://registry.npmjs.org/${name}/${version}`);
    if (!response.ok) {
      if (response.status === 404) {
        return null;
      }
      return null;
    }
    return await response.json();
  } catch (error) {
    console.warn(`Failed to fetch manifest for ${name}@${version}: ${error.message}`);
    return null;
  }
}

/**
 * Check for potentially dangerous install scripts in package.json
 * Only flag packages under 30 days old with preinstall, install, or postinstall scripts
 * Reads scripts from each dependency's registry metadata (versions[lockedVersion].scripts)
 */
async function checkInstallScripts(targetPath, dependencies) {
  const findings = [];
  
  for (const [name, dep] of Object.entries(dependencies)) {
    const metadata = await getPackageMetadata(name);
    
    if (!metadata || !metadata.created) {
      continue;
    }
    
    const createdDaysAgo = daysSince(metadata.created);
    
    // Only flag if package is under 30 days old
    if (createdDaysAgo >= 30) {
      continue;
    }
    
    // Get the locked version
    const lockedVersion = dep.version;
    if (!lockedVersion) {
      continue;
    }
    
    // Fetch the package manifest for the locked version to get its scripts
    const manifest = await getPackageManifest(name, lockedVersion);
    if (!manifest || !manifest.scripts) {
      continue;
    }
    
    // Check for dangerous scripts in THIS dependency's manifest
    const dangerousScripts = ['preinstall', 'install', 'postinstall'];
    const scriptsToReport = [];
    
    for (const script of dangerousScripts) {
      if (manifest.scripts[script]) {
        scriptsToReport.push(script);
      }
    }
    
    if (scriptsToReport.length === 0) {
      continue;
    }
    
    findings.push({
      type: 'Install Script',
      package: name,
      version: lockedVersion,
      severity: 'medium',
      confidence: 'medium',
      redacted: name,
      summary: `Package "${name}" (${createdDaysAgo} days old) has install scripts: ${scriptsToReport.join(', ')}`,
      details: `Scripts: ${scriptsToReport.map(s => `${s}: ${manifest.scripts[s]}`).join('; ')}`,
      file: 'package.json',
      line: 0,
      fixPrompt: `Review install scripts for "${name}" before installation. Consider using --ignore-scripts flag.`
    });
  }
  
  return findings;
}

module.exports = { checkInstallScripts };