const fs = require('fs').promises;
const path = require('path');
const { createProvider, generateCacheKey } = require('./providers');
const { TriageCache } = require('./cache');

/**
 * Triage findings (secrets or dependencies) with configurable AI providers.
 * Sends only masked secrets or dependency metadata - never raw secrets.
 * Marks each finding triage: 'important' | 'noise'.
 * 
 * Env vars:
 * - SHRINE_TRIAGE_PROVIDER: mistral | openrouter | groq (default: mistral)
 * - SHRINE_TRIAGE_MODEL: model name (defaults per provider)
 * - SHRINE_TRIAGE_KEY: API key (fallback: MISTRAL_API_KEY for mistral)
 */
async function triageFindings(findings, options = {}) {
  if (findings.length === 0) {
    return findings;
  }

  // Determine provider and API key
  const providerName = process.env.SHRINE_TRIAGE_PROVIDER || 'mistral';
  const model = process.env.SHRINE_TRIAGE_MODEL || options.model;
  let apiKey = process.env.SHRINE_TRIAGE_KEY || options.apiKey;
  
  // Fallback to MISTRAL_API_KEY for mistral provider
  if (providerName === 'mistral' && !apiKey) {
    apiKey = process.env.MISTRAL_API_KEY;
  }

  if (!apiKey) {
    // Determine which env var to suggest
    const keyEnvVar = providerName === 'mistral' 
      ? 'MISTRAL_API_KEY or SHRINE_TRIAGE_KEY'
      : 'SHRINE_TRIAGE_KEY';
    console.log(`\nTriage skipped: no API key found. Set ${keyEnvVar} to enable triage.`);
    
    // Mark all findings as skipped
    for (const finding of findings) {
      finding.triage = 'skipped';
    }
    return findings;
  }

  // Build request items based on finding type
  const items = [];
  const isDependency = findings[0] && 'package' in findings[0];

  if (isDependency) {
    // Dependency findings: send package, version, type, severity
    for (const finding of findings) {
      items.push({
        package: finding.package,
        version: finding.version,
        type: finding.type,
        severity: finding.severity
      });
    }
  } else {
    // Secret findings: masked match + line (secret masked in-line)
    for (const finding of findings) {
      if (!finding.file || !finding.line) {
        continue;
      }
      let lineContent = '';
      try {
        const filePath = path.isAbsolute(finding.file)
          ? finding.file
          : path.join(options.scanRoot || process.cwd(), finding.file);
        const content = await fs.readFile(filePath, 'utf-8');
        lineContent = content.split('\n')[finding.line - 1] || '';
      } catch (error) {
        lineContent = '';
      }

      const masked = finding.redacted || finding.match || '';
      const safeLine = finding.match ? lineContent.split(finding.match).join(masked) : lineContent;

      items.push({
        file: finding.file,
        line: finding.line,
        type: finding.type,
        match: masked,
        context: safeLine
      });
    }
  }

  if (items.length === 0) {
    return findings;
  }

  // Check cache
  const cache = new TriageCache();
  const cacheKey = generateCacheKey(items);
  const cachedVerdicts = await cache.get(cacheKey);

  if (cachedVerdicts) {
    // Apply cached verdicts
    const verdictMap = new Map(cachedVerdicts.map(v => [v.id, v.verdict]));
    for (let i = 0; i < findings.length; i++) {
      findings[i].triage = verdictMap.get(i + 1) === 'noise' ? 'noise' : 'important';
    }
    return findings;
  }

  // Create provider
  let provider;
  try {
    provider = createProvider(providerName, apiKey, model);
  } catch (error) {
    console.log(`\nTriage configuration error: ${error.message}. Showing all findings.`);
    return findings;
  }

  // Batch in chunks of 20
  const BATCH = 20;
  const allVerdicts = [];

  for (let i = 0; i < items.length; i += BATCH) {
    const batch = items.slice(i, i + BATCH);
    
    try {
      const verdicts = await provider.triage(batch);
      const verdictMap = new Map(verdicts.map(v => [v.id, v.verdict]));

      for (let j = 0; j < batch.length; j++) {
        const verdict = verdictMap.get(j + 1) === 'noise' ? 'noise' : 'important';
        findings[i + j].triage = verdict;
        allVerdicts.push({ id: i + j + 1, verdict });
      }
    } catch (error) {
      console.log(`\n${providerName} triage failed: ${error.message}. Showing all findings.`);
      // Mark all as important on failure
      for (let j = 0; j < findings.length; j++) {
        if (!findings[j].triage) {
          findings[j].triage = 'important';
        }
      }
      return findings;
    }
  }

  // Cache the verdicts
  await cache.set(cacheKey, allVerdicts);

  return findings;
}

module.exports = { triageFindings };
