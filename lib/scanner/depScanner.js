const fs = require('fs').promises;
const path = require('path');
const { daysSince, formatDate, parseVersion } = require('./depUtils');

/**
 * Read package dependencies from package-lock.json or package.json
 * Follows npm's locking precedence: package-lock > package.json
 */
async function readDependencies(targetPath) {
  const lockPath = path.join(targetPath, 'package-lock.json');
  const packagePath = path.join(targetPath, 'package.json');
  
  let dependencies = {};
  
  // Try package-lock.json first (npm) - preferred source with locked versions
  try {
    const lockData = await fs.readFile(lockPath, 'utf-8');
    const lock = JSON.parse(lockData);
    
    // Extract dependencies from lockfile
    if (lock.dependencies) {
      Object.keys(lock.dependencies).forEach(name => {
        const dep = lock.dependencies[name];
        // Skip file:, workspace:, git: and link: specs
        if (dep.version && !dep.version.startsWith('file:') && 
            !dep.version.startsWith('workspace:') && 
            !dep.version.startsWith('git+') && 
            !dep.version.startsWith('link:')) {
          // Parse name from last "node_modules/" segment
          const nameMatch = dep.source ? dep.source.match(/node_modules\\([^\\/]+)$/) : null;
          const packageName = nameMatch ? nameMatch[1] : name;
          dependencies[packageName] = {
            version: dep.version,
            source: 'lockfile'
          };
        }
      });
    }
  } catch (error) {
    // Ignore - fall back to package.json
  }
  
  // Fall back to package.json if lockfile not available
  try {
    const packageData = await fs.readFile(packagePath, 'utf-8');
    const pkg = JSON.parse(packageData);
    
    // Extract dependencies from package.json
    const deps = { ...pkg.dependencies, ...pkg.devDependencies };
    Object.keys(deps).forEach(name => {
      // Skip file:, workspace:, git: and link: specs
      if (deps[name] && !deps[name].startsWith('file:') && 
          !deps[name].startsWith('workspace:') && 
          !deps[name].startsWith('git+') && 
          !deps[name].startsWith('link:')) {
        // Use version range from package.json (without ^, ~, etc)
        const cleanedVersion = deps[name].replace(/^[~^><=]+/, '').split('.')[0] === '*' ? null : deps[name].replace(/^[~^><=]+/, '');
        dependencies[name] = {
          version: dependencies[name]?.version || cleanedVersion,
          source: dependencies[name] ? 'lockfile' : 'package.json'
        };
      }
    });
  } catch (error) {
    // Ignore
  }
  
  return dependencies;
}

module.exports = { readDependencies };