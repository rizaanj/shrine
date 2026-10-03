const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
const { daysSince } = require('./depUtils');

// Skip packages under this character count
const MIN_NAME_LENGTH = 5;

// Cache for npm registry metadata
const metadataCache = new Map();

/**
 * Simple Levenshtein distance calculation for typo detection
 */
function levenshtein(a, b) {
  const matrix = [];
  
  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }
  
  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }
  
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }
  
  return matrix[b.length][a.length];
}

/**
 * Check if a package name is in the top 1000 popular packages
 */
async function isTopPackage(name) {
  // In a real implementation, this would query a list of top packages
  // For now, we'll use a simple heuristic based on download count
  const metadata = await getPackageMetadata(name);
  if (!metadata) return false;
  
  // Packages with over 1M weekly downloads are considered top
  return metadata.downloads && metadata.downloads > 1000000;
}

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
      return null;
    }
    
    const data = await response.json();
    
    // Extract relevant metadata
    const metadata = {
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
 * Check dependencies for typosquatting risks
 */
async function checkTyposquat(dependencies) {
  const findings = [];
  
  // In a real implementation, we would have a list of popular package names
  // For now, we'll use a simple heuristic based on name length, age, and download count
  
  for (const [name, dep] of Object.entries(dependencies)) {
    // Skip short names
    if (name.length < MIN_NAME_LENGTH) {
      continue;
    }
    
    // Skip top 1000 packages
    if (await isTopPackage(name)) {
      continue;
    }
    
    const metadata = await getPackageMetadata(name);
    if (!metadata) {
      continue;
    }
    
    const createdDaysAgo = metadata.created ? daysSince(metadata.created) : null;
    
    // Flag if package is under 30 days old or has low downloads
    const isNew = createdDaysAgo !== null && createdDaysAgo < 30;
    const isLowDownload = metadata.downloads < 100;
    
    if (isNew || isLowDownload) {
      findings.push({
        type: 'Typosquat Risk',
        package: name,
        version: dep.version,
        severity: 'medium',
        summary: `Package is ${isNew ? `${createdDaysAgo} days old` : `has low downloads (${metadata.downloads})`}`,
        details: `Created: ${metadata.created ? metadata.created.toISOString().split('T')[0] : 'unknown'}, Downloads: ${metadata.downloads || 'unknown'}, Versions: ${metadata.versionCount}`,
        url: `https://www.npmjs.com/package/${name}`,
        file: 'package.json',
        line: 0,
        fixPrompt: `Review "${name}" for legitimacy. ${isNew ? 'New packages may lack community vetting.' : 'Low download counts may indicate an unpopular or potentially malicious package.'}`
      });
    }
  }
  
  return findings;
}

module.exports = { checkTyposquat };