const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
const { daysSince } = require('./depUtils');

// Cache for npm registry metadata
const metadataCache = new Map();

/**
 * Get package metadata from npm registry with caching
 */
async function getPackageMetadata(name) {
  if (metadataCache.has(name)) {
    return metadataCache.get(name);
  }

  try {
    const response = await fetch(`https://registry.npmjs.org/${name}`);
    if (!response.ok) {
      if (response.status === 404) {
        return { exists: false };
      }
      return null;
    }
    
    const data = await response.json();
    
    // Extract relevant metadata
    const metadata = {
      exists: true,
      created: data.time?.created ? new Date(data.time.created) : null,
      updatedAt: data.time?.modified ? new Date(data.time.modified) : null,
      downloads: data?.downloads?.weekly || 0,
      keywords: data.keywords || [],
      versionCount: Object.keys(data.versions || {}).length
    };
    
    metadataCache.set(name, metadata);
    return metadata;
  } catch (error) {
    console.warn(`Failed to fetch metadata for ${name}: ${error.message}`);
    return null;
  }
}

/**
 * Check dependencies for nonexistent or new packages
 */
async function checkRegistry(dependencies) {
  const findings = [];
  let networkErrorWarned = false;
  
  for (const [name, dep] of Object.entries(dependencies)) {
    const metadata = await getPackageMetadata(name);
    
    if (metadata === null) {
      // Network error
      if (!networkErrorWarned) {
        console.warn('Failed to reach npm registry. Skipping package existence checks.');
        networkErrorWarned = true;
      }
      continue;
    }
    
    if (metadata.exists === false) {
      // 404 - Nonexistent package
      findings.push({
        type: 'Nonexistent Package',
        package: name,
        version: dep.version,
        severity: 'high',
        summary: `Package "${name}" does not exist in npm registry`,
        details: `This package was not found in the npm registry. It may have been unpublished or the name is misspelled.`,
        url: `https://www.npmjs.com/package/${name}`,
        file: 'package.json',
        line: 0,
        fixPrompt: `Remove "${name}" from dependencies or check for typos in the package name.`
      });
      continue;
    }
    
    // Check if package is under 30 days old
    if (metadata.created) {
      const createdDaysAgo = daysSince(metadata.created);
      
      if (createdDaysAgo < 30) {
        findings.push({
          type: 'New Package',
          package: name,
          version: dep.version,
          severity: 'medium',
          summary: `Package "${name}" was created ${createdDaysAgo} days ago`,
          details: `Created: ${metadata.created.toISOString().split('T')[0]}, Downloads: ${metadata.downloads || 0}, Versions: ${metadata.versionCount}`,
          url: `https://www.npmjs.com/package/${name}`,
          file: 'package.json',
          line: 0,
          fixPrompt: `Review "${name}" for legitimacy. New packages may lack community vetting.`,
          metadata: metadata
        });
      }
    }
  }
  
  return findings;
}

module.exports = { checkRegistry, getPackageMetadata };
