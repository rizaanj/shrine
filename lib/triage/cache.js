const fs = require('fs').promises;
const path = require('path');

/**
 * Cache manager for triage verdicts
 */
class TriageCache {
  constructor(cacheDir = '.shrine-cache/triage') {
    this.cacheDir = path.resolve(cacheDir);
  }

  async ensureCacheDir() {
    try {
      await fs.mkdir(this.cacheDir, { recursive: true });
    } catch (error) {
      // Ignore if already exists
    }
  }

  /**
   * Get cached verdicts by key
   * @param {string} key - Cache key
   * @returns {Promise<Object|null>} Cached data or null if expired/missing
   */
  async get(key) {
    const cacheFile = path.join(this.cacheDir, `${key}.json`);
    
    try {
      const content = await fs.readFile(cacheFile, 'utf-8');
      const data = JSON.parse(content);
      
      // Check if cache is still valid (24 hours)
      const age = Date.now() - data.timestamp;
      const MAX_AGE = 24 * 60 * 60 * 1000; // 24 hours in ms
      
      if (age > MAX_AGE) {
        // Expired, remove it
        await fs.unlink(cacheFile).catch(() => {});
        return null;
      }
      
      return data.verdicts;
    } catch (error) {
      return null;
    }
  }

  /**
   * Store verdicts in cache
   * @param {string} key - Cache key
   * @param {Array} verdicts - Verdict array
   */
  async set(key, verdicts) {
    await this.ensureCacheDir();
    
    const cacheFile = path.join(this.cacheDir, `${key}.json`);
    const data = {
      timestamp: Date.now(),
      verdicts
    };
    
    try {
      await fs.writeFile(cacheFile, JSON.stringify(data, null, 2), 'utf-8');
    } catch (error) {
      // Cache write failure is non-fatal
    }
  }

  /**
   * Clear all cache entries
   */
  async clear() {
    try {
      const files = await fs.readdir(this.cacheDir);
      await Promise.all(
        files.filter(f => f.endsWith('.json')).map(f =>
          fs.unlink(path.join(this.cacheDir, f)).catch(() => {})
        )
      );
    } catch (error) {
      // Ignore errors
    }
  }
}

module.exports = { TriageCache };
