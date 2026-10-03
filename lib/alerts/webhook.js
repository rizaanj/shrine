const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

async function sendAlert(finding, options = {}) {
  const { webhookUrl, verbose, cacheDir } = options;
  
  if (!webhookUrl) {
    return false;
  }

  const hashInput = finding.type + finding.severity + (finding.file || 'global') + finding.line;
  const hash = crypto.createHash('sha256').update(hashInput).digest('hex').slice(0, 16);
  
  const cacheFile = path.join(cacheDir, `${hash}.json`);
  
  try {
    if (fs.existsSync(cacheFile)) {
      const cached = JSON.parse(fs.readFileSync(cacheFile, 'utf8'));
      const now = Date.now();
      if (now - cached.timestamp < 60 * 60 * 1000) {
        if (verbose) {
          console.log(`Alert rate-limited for ${finding.type} (${finding.severity})`);
        }
        return false;
      }
    }
  } catch (e) {
  }

  const redacted = finding.redacted || finding.evidence?.bodyTruncated?.slice(0, 100) || 'N/A';
  
  const payload = {
    timestamp: new Date().toISOString(),
    severity: finding.severity,
    type: finding.type,
    file: finding.file || 'global',
    line: finding.line,
    message: finding.message || `${finding.type} detected`,
    redacted
  };

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);

  try {
    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal
    });
    clearTimeout(timeout);
    
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    
    fs.mkdirSync(cacheDir, { recursive: true });
    fs.writeFileSync(cacheFile, JSON.stringify({ timestamp: Date.now() }));
    
    if (verbose) {
      console.log(`Alert sent for ${finding.type} (${finding.severity})`);
    }
    return true;
  } catch (err) {
    clearTimeout(timeout);
    console.warn('Alert skipped: ' + err.message);
    return false;
  }
}

module.exports = { sendAlert };