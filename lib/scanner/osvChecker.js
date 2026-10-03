const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
const fs = require('fs').promises;
const path = require('path');

const CACHE_DIR = path.join(__dirname, '../../.shrine-cache/osv');
const CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

/**
 * Initialize cache directory
 */
async function initCache() {
  try {
    await fs.mkdir(CACHE_DIR, { recursive: true });
  } catch (error) {
    console.error(`Failed to create OSV cache directory: ${error.message}`);
  }
}

/**
 * Get cache path for a package
 */
function getCachePath(name) {
  const safeName = name.replace(/[^a-z0-9]/g, '_');
  return path.join(CACHE_DIR, `${safeName}.json`);
}

/**
 * Read from cache
 */
async function readFromCache(name) {
  const cachePath = getCachePath(name);
  try {
    const stat = await fs.stat(cachePath);
    if (Date.now() - stat.mtimeMs > CACHE_TTL) {
      await fs.unlink(cachePath);
      return null;
    }
    const data = await fs.readFile(cachePath, 'utf-8');
    return JSON.parse(data);
  } catch (error) {
    return null;
  }
}

/**
 * Write to cache
 */
async function writeToCache(name, data) {
  const cachePath = getCachePath(name);
  try {
    await fs.writeFile(cachePath, JSON.stringify(data), 'utf-8');
  } catch (error) {
    console.error(`Failed to cache OSV data for ${name}: ${error.message}`);
  }
}

/**
 * Query OSV API for a batch of packages
 */
async function queryOSVBatch(packages) {
  const BATCH_SIZE = 1000;
  const results = [];

  for (let i = 0; i < packages.length; i += BATCH_SIZE) {
    const batch = packages.slice(i, i + BATCH_SIZE);
    try {
      const response = await fetch('https://api.osv.dev/v1/querybatch', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          queries: batch.map(pkg => ( {
            version: pkg.version,
            package: {
              name: pkg.name,
              ecosystem: 'npm'
            }
          }))
        })
      });

      if (!response.ok) {
        throw new Error(`OSV API error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      results.push(...data.results);
    } catch (error) {
      console.warn(`OSV batch query failed: ${error.message}`);
      break;
    }
  }

  return results;
}

/**
 * Get detailed vulnerability information from OSV
 */
async function getVulnerabilityDetails(vulnId) {
  try {
    const response = await fetch(`https://api.osv.dev/v1/vulns/${vulnId}`);
    if (!response.ok) {
      throw new Error(`OSV detail query failed: ${response.status}`);
    }
    return await response.json();
  } catch (error) {
    console.warn(`Failed to get details for ${vulnId}: ${error.message}`);
    return null;
  }
}

/**
 * Check dependencies for known vulnerabilities using OSV
 */
async function checkOSV(dependencies) {
  await initCache();

  const findings = [];
  const packages = Object.entries(dependencies)
    .filter(([_, dep]) => dep.version)
    .map(([name, dep]) => ({ name, version: dep.version }));

  if (packages.length === 0) {
    return findings;
  }

  // Query OSV API in batches
  const results = await queryOSVBatch(packages);
  if (!results || results.length === 0) {
    console.warn('Failed to reach OSV API or registry. Skipping vulnerability checks.');
    return findings;
  }

  // Process results - results array corresponds to packages array by index
  for (let i = 0; i < results.length; i++) {
    const result = results[i];
    const pkg = packages[i];
    
    if (!result.vulns || result.vulns.length === 0) {
      continue;
    }

    const pkgName = pkg.name;
    const vulns = result.vulns;

    for (const vuln of vulns) {
      const cachedData = await readFromCache(pkgName + '_' + vuln.id);
      const details = cachedData || await getVulnerabilityDetails(vuln.id);
      
      if (details) {
        await writeToCache(pkgName + '_' + vuln.id, details);
      }

      // Extract severity - use database_specific.severity as primary, CVSS as fallback
      let severity = 'high';
      let severitySource = 'default';
      
      // Primary: database_specific.severity (most reliable)
      if (details?.database_specific?.severity) {
        const dbSev = details.database_specific.severity.toUpperCase();
        if (dbSev === 'CRITICAL') severity = 'critical';
        else if (dbSev === 'HIGH') severity = 'high';
        else if (dbSev === 'MODERATE') severity = 'medium';
        else if (dbSev === 'LOW') severity = 'low';
        severitySource = 'database_specific';
      }
      
      // Fallback: parse CVSS vector if database_specific not available
      if (severitySource === 'default' && details?.severity && details.severity.length > 0) {
        for (const sev of details.severity) {
          if (sev.type === 'CVSS_V3' && sev.score) {
            // Use CIA impact to estimate severity
            // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
            const ciaMatch = sev.score.match(/C:([HLN])\/I:([HLN])\/A:([HLN])/);
            if (ciaMatch) {
              const impacts = { H: 3, L: 1, N: 0 };
              const c = impacts[ciaMatch[1]] || 0;
              const i = impacts[ciaMatch[2]] || 0;
              const a = impacts[ciaMatch[3]] || 0;
              const totalImpact = c + i + a;
              
              if (totalImpact >= 7) severity = 'critical';
              else if (totalImpact >= 5) severity = 'high';
              else if (totalImpact >= 2) severity = 'medium';
              else severity = 'low';
              severitySource = 'CVSS_V3_CIA';
              break;
            }
          }
        }
      }

      // Extract fixed version
      let fixedVersion = 'Unknown';
      if (details?.affected) {
        for (const affected of details.affected) {
          if (affected.package?.ecosystem === 'npm' && affected.package?.name === pkgName) {
            if (affected.ranges) {
              for (const range of affected.ranges) {
                if (range.type === 'SEMVER' && range.events) {
                  const fixedEvent = range.events.find(e => e.fixed);
                  if (fixedEvent && fixedEvent.fixed) {
                    fixedVersion = fixedEvent.fixed;
                    break;
                  }
                }
              }
            }
            if (fixedVersion !== 'Unknown') break;
          }
        }
      }

      // Log raw severity fields for debugging
      if (process.env.SHRINE_DEBUG_OSV) {
        console.log(`[OSV] ${vuln.id} for ${pkgName}:`);
        console.log(`  severity array: ${JSON.stringify(details?.severity)}`);
        console.log(`  database_specific.severity: ${details?.database_specific?.severity}`);
        console.log(`  mapped severity: ${severity} (source: ${severitySource})`);
      }
      
      findings.push({
        type: 'OSV Vulnerability',
        package: pkgName,
        version: pkg.version,
        id: vuln.id,
        severity: severity,
        summary: details?.summary || details?.details || 'No summary available',
        fixedVersion: fixedVersion,
        url: `https://osv.dev/vulnerability/${vuln.id}`,
        file: 'package.json',
        line: 0,
        fixPrompt: fixedVersion !== 'Unknown' 
          ? `Update ${pkgName} to version ${fixedVersion} or later to fix ${vuln.id}`
          : `Review ${vuln.id} at https://osv.dev/vulnerability/${vuln.id} and update ${pkgName} if a fix is available`,
        rawSeverity: {
          cvss: details?.severity?.[0]?.score || null,
          databaseSpecific: details?.database_specific?.severity || null,
          source: severitySource
        }
      });
    }
  }

  return findings;
}

module.exports = { checkOSV };