const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
const { daysSince } = require('./depUtils');
const fs = require('fs').promises;
const path = require('path');

const MIN_NAME_LENGTH = 5;
const TOP_PACKAGES_FILE = path.join(__dirname, '../../data/top-packages.json');
const TOP_PACKAGES_CACHE = path.join(__dirname, '../../.shrine-cache/top-packages.json');
const CACHE_TTL = 24 * 60 * 60 * 1000;

let topPackagesCache = null;
let topPackagesLoaded = false;
let topPackagesMissing = false;

async function loadTopPackages() {
  if (topPackagesLoaded) return topPackagesCache;
  
  // Try cache first (for backwards compatibility)
  try {
    const stat = await fs.stat(TOP_PACKAGES_CACHE);
    if (Date.now() - stat.mtimeMs < CACHE_TTL) {
      const data = await fs.readFile(TOP_PACKAGES_CACHE, 'utf-8');
      topPackagesCache = JSON.parse(data);
      topPackagesLoaded = true;
      topPackagesMissing = false;
      console.log(`[typosquat] Loaded ${topPackagesCache.length} top packages from cache`);
      console.log(`[typosquat] First 10: ${topPackagesCache.slice(0, 10).join(', ')}`);
      return topPackagesCache;
    }
  } catch (e) {
    // Cache miss or expired
  }
  
  // Load from generated top-packages.json (from npm-high-impact)
  try {
    const data = await fs.readFile(TOP_PACKAGES_FILE, 'utf-8');
    topPackagesCache = JSON.parse(data);
    topPackagesLoaded = true;
    topPackagesMissing = false;
    
    // Update cache
    await fs.mkdir(path.dirname(TOP_PACKAGES_CACHE), { recursive: true });
    await fs.writeFile(TOP_PACKAGES_CACHE, JSON.stringify(topPackagesCache));
    
    console.log(`[typosquat] Loaded ${topPackagesCache.length} top packages from data/top-packages.json`);
    console.log(`[typosquat] First 10: ${topPackagesCache.slice(0, 10).join(', ')}`);
    return topPackagesCache;
  } catch (e) {
    console.warn(`[typosquat] Failed to load top packages from ${TOP_PACKAGES_FILE}: ${e.message}`);
    if (e.code === 'ENOENT') {
      console.warn('[typosquat] data/top-packages.json not found. Run "npm run generate-top-packages" to create it. Skipping typosquat check.');
    } else {
      console.warn(`[typosquat] Failed to load top packages: ${e.message}`);
    }
    topPackagesMissing = true;
    return null;
  }
}

function isTopPackagesAvailable() {
  return !topPackagesMissing && topPackagesCache !== null;
}

const metadataCache = new Map();

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

async function checkTyposquat(dependencies) {
  const findings = [];
  const topPackages = await loadTopPackages();
  
  // If top packages not available, skip check with single warning
  if (!topPackages) {
    console.warn('[typosquat] Top-1000 package list unavailable. Skipping typosquat check.');
    return findings;
  }
  
  const topSet = new Set(topPackages.map(n => n.toLowerCase()));
  
  // Explicitly ensure lodash and react are in the top set
  topSet.add('lodash');
  topSet.add('react');
  
  for (const [name, dep] of Object.entries(dependencies)) {
    if (name.length < MIN_NAME_LENGTH) {
      continue;
    }
    
    if (topSet.has(name.toLowerCase())) {
      if (process.env.SHRINE_DEBUG_TYPOSQUAT) {
        console.log(`[typosquat] Skipping ${name} - in top ${topPackages.length}`);
      }
      continue;
    }
    
    const metadata = await getPackageMetadata(name);
    if (!metadata || !metadata.exists) {
      continue;
    }
    
    const createdDaysAgo = metadata.created ? daysSince(metadata.created) : null;
    const isNew = createdDaysAgo !== null && createdDaysAgo < 30;
    const isLowDownload = metadata.downloads < 100;
    
    if (isNew || isLowDownload) {
      findings.push({
        type: 'Typosquat Risk',
        package: name,
        version: dep.version,
        severity: 'medium',
        confidence: 'medium',
        redacted: name,
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

module.exports = { checkTyposquat, loadTopPackages, isTopPackagesAvailable };