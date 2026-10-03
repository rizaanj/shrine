const crypto = require('crypto');

/**
 * Base provider interface for triage services
 */
class TriageProvider {
  constructor(apiKey, model) {
    this.apiKey = apiKey;
    this.model = model;
  }

  /**
   * Send items to the provider for triage
   * @param {Array} items - Array of {file, line, type, match, context} or {package, version, type, severity}
   * @returns {Promise<Array>} Array of {id, verdict} where verdict is 'important' or 'noise'
   */
  async triage(items) {
    throw new Error('triage() must be implemented by provider');
  }

  /**
   * Generate a prompt for the given items
   */
  generatePrompt(items) {
    const hasPackage = items[0] && 'package' in items[0];
    
    if (hasPackage) {
      return `You are triaging dependency vulnerability findings.
For each item decide: "important" (real security risk) or "noise" (low severity, acceptable risk, or false positive).

Respond ONLY with a JSON array like: [{"id":1,"verdict":"important"}]

Items:
${JSON.stringify(items.map((item, idx) => ({ id: idx + 1, ...item })), null, 2)}`;
    }

    return `You are triaging potential secret detections from a code scanner.
For each item decide: "important" (likely a real exposed secret) or "noise" (false positive, placeholder, or sample value).

Respond ONLY with a JSON array like: [{"id":1,"verdict":"important"}]

Items:
${JSON.stringify(items.map((item, idx) => ({ id: idx + 1, ...item })), null, 2)}`;
  }

  /**
   * Parse response text to extract verdicts
   */
  parseVerdicts(text) {
    const jsonMatch = text.match(/\[[\s\S]*\]/);
    return jsonMatch ? JSON.parse(jsonMatch[0]) : [];
  }
}

/**
 * Mistral provider (Codestral)
 */
class MistralProvider extends TriageProvider {
  async triage(items) {
    const prompt = this.generatePrompt(items);
    
    const res = await fetch('https://api.mistral.ai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.apiKey}`
      },
      body: JSON.stringify({
        model: this.model || 'codestral-latest',
        messages: [{ role: 'user', content: prompt }],
        temperature: 0
      })
    });

    if (!res.ok) {
      throw new Error(`Mistral API failed: HTTP ${res.status}`);
    }

    const data = await res.json();
    const text = (data.choices?.[0]?.message?.content) || '';
    return this.parseVerdicts(text);
  }
}

/**
 * OpenRouter provider
 */
class OpenRouterProvider extends TriageProvider {
  async triage(items) {
    const prompt = this.generatePrompt(items);
    
    const res = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.apiKey}`,
        'HTTP-Referer': 'https://github.com/shrine-security/shrine',
        'X-Title': 'Shrine Security Scanner'
      },
      body: JSON.stringify({
        model: this.model || 'anthropic/claude-3.5-sonnet',
        messages: [{ role: 'user', content: prompt }],
        temperature: 0
      })
    });

    if (!res.ok) {
      throw new Error(`OpenRouter API failed: HTTP ${res.status}`);
    }

    const data = await res.json();
    const text = (data.choices?.[0]?.message?.content) || '';
    return this.parseVerdicts(text);
  }
}

/**
 * Groq provider
 */
class GroqProvider extends TriageProvider {
  async triage(items) {
    const prompt = this.generatePrompt(items);
    
    const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.apiKey}`
      },
      body: JSON.stringify({
        model: this.model || 'llama-3.1-70b-versatile',
        messages: [{ role: 'user', content: prompt }],
        temperature: 0
      })
    });

    if (!res.ok) {
      throw new Error(`Groq API failed: HTTP ${res.status}`);
    }

    const data = await res.json();
    const text = (data.choices?.[0]?.message?.content) || '';
    return this.parseVerdicts(text);
  }
}

/**
 * Factory to create the appropriate provider
 */
function createProvider(providerName, apiKey, model) {
  const providers = {
    mistral: MistralProvider,
    openrouter: OpenRouterProvider,
    groq: GroqProvider
  };

  const Provider = providers[providerName?.toLowerCase()];
  if (!Provider) {
    throw new Error(`Unknown provider: ${providerName}. Valid options: mistral, openrouter, groq`);
  }

  return new Provider(apiKey, model);
}

/**
 * Generate cache key for findings or dependencies
 * 
 * Cache key inputs (all masked, no raw secrets):
 * 
 * For secret findings:
 *   - file: relative file path
 *   - line: line number
 *   - type: finding type (e.g., 'API_KEY', 'PRIVATE_KEY')
 *   - match: MASKED value only (e.g., 'sk_live_***')
 * 
 * For dependency findings:
 *   - package: package name (e.g., 'lodash')
 *   - version: version string (e.g., '4.17.20')
 *   - type: finding type (e.g., 'outdated', 'vulnerability')
 *   - severity: severity level (e.g., 'high', 'medium', 'low')
 * 
 * The inputs are normalized, sorted, joined with '|', and hashed with SHA256.
 * Result is a 64-character hexadecimal string.
 * 
 * @param {Array} items - Array of finding metadata (masked values only)
 * @returns {string} SHA256 hash (64 hex chars)
 */
function generateCacheKey(items) {
  const normalized = items.map(item => {
    if ('package' in item) {
      return `${item.package}@${item.version}:${item.type}:${item.severity}`;
    }
    return `${item.file}:${item.line}:${item.type}:${item.match}`;
  }).sort().join('|');
  
  return crypto.createHash('sha256').update(normalized).digest('hex');
}

module.exports = {
  TriageProvider,
  MistralProvider,
  OpenRouterProvider,
  GroqProvider,
  createProvider,
  generateCacheKey
};
