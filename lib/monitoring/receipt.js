const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Generate a receipt from scan results
 * @param {Object} params
 * @param {Array} params.findings - All findings from scan
 * @param {number} params.filesScanned - Number of files scanned
 * @param {Array} params.tables - Supabase tables with RLS info
 * @returns {Object} Receipt with timestamp, hashes, and metadata
 */
function generateReceipt({ findings, filesScanned, tables }) {
  // Generate schema hash
  let schemaHash;
  if (!tables || tables.length === 0) {
    schemaHash = 'no-supabase';
  } else {
    const schemaData = tables
      .map(t => `${t.table_name}:${t.rls_enabled}:${t.policy_count}`)
      .sort()
      .join('|');
    schemaHash = crypto.createHash('sha256').update(schemaData).digest('hex').slice(0, 16);
  }

  // Generate findings hash
  const findingsData = findings
    .map(f => `${f.type}:${f.severity}:${f.file || 'global'}`)
    .sort()
    .join('|');
  const findingsHash = crypto.createHash('sha256').update(findingsData).digest('hex').slice(0, 16);

  return {
    timestamp: Date.now(),
    filesScanned,
    schemaHash,
    findingsHash,
    version: '1.0.2'
  };
}

/**
 * Save receipt to .shrine/receipt.json
 * @param {string} targetPath - Base directory path
 * @param {Object} receipt - Receipt to save
 */
function saveReceipt(targetPath, receipt) {
  try {
    const shrineDir = path.join(targetPath, '.shrine');
    fs.mkdirSync(shrineDir, { recursive: true });
    const receiptPath = path.join(shrineDir, 'receipt.json');
    fs.writeFileSync(receiptPath, JSON.stringify(receipt, null, 2), 'utf8');
  } catch (error) {
    console.error(`Failed to save receipt: ${error.message}`);
  }
}

/**
 * Load receipt from .shrine/receipt.json
 * @param {string} targetPath - Base directory path
 * @returns {Object|null} Receipt or null if not found/invalid
 */
function loadReceipt(targetPath) {
  try {
    const receiptPath = path.join(targetPath, '.shrine', 'receipt.json');
    const data = fs.readFileSync(receiptPath, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    return null;
  }
}

/**
 * Check if receipt is stale
 * @param {Object} currentReceipt - Current receipt
 * @param {Object} savedReceipt - Previously saved receipt
 * @returns {Object} {stale: boolean, reason: string|null}
 */
function isStale(currentReceipt, savedReceipt) {
  try {
    if (!savedReceipt || !currentReceipt) {
      return { stale: false, reason: null };
    }

    if (savedReceipt.schemaHash !== currentReceipt.schemaHash) {
      return { stale: true, reason: 'schema changed' };
    }

    if (savedReceipt.findingsHash !== currentReceipt.findingsHash) {
      return { stale: true, reason: 'findings changed' };
    }

    const age = Date.now() - (savedReceipt.timestamp || 0);
    if (age > 24 * 60 * 60 * 1000) {
      return { stale: true, reason: 'expired' };
    }

    return { stale: false, reason: null };
  } catch (error) {
    return { stale: false, reason: null };
  }
}

module.exports = {
  generateReceipt,
  saveReceipt,
  loadReceipt,
  isStale
};
