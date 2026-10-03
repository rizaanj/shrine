const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { TriageProvider, createProvider, generateCacheKey } = require('./providers');
const { triageFindings } = require('./codestral');
const { TriageCache } = require('./cache');
const fs = require('fs').promises;
const path = require('path');

/**
 * Mock fetch to intercept outgoing requests and verify no secrets are sent
 */
let capturedRequests = [];

global.fetch = async (url, options) => {
  const request = {
    url,
    headers: options?.headers || {},
    body: options?.body ? JSON.parse(options.body) : null
  };
  capturedRequests.push(request);

  // Return mock response
  return {
    ok: true,
    json: async () => ({
      choices: [{
        message: {
          content: '[{"id":1,"verdict":"noise"}]'
        }
      }]
    })
  };
};

describe('Triage Security Tests', () => {
  before(() => {
    capturedRequests = [];
  });

  after(async () => {
    // Cleanup test cache
    const cache = new TriageCache('.shrine-cache/triage-test');
    await cache.clear();
  });

  it('should never send raw secrets in request body', async () => {
    const findings = [
      {
        file: 'test.js',
        line: 1,
        type: 'API_KEY',
        match: 'sk_live_abc123xyz789secret',
        redacted: 'sk_live_***'
      }
    ];

    await triageFindings(findings, {
      apiKey: 'test-key',
      scanRoot: __dirname
    });

    // Check that no request contained the raw secret
    for (const req of capturedRequests) {
      const bodyStr = JSON.stringify(req.body);
      assert.ok(
        !bodyStr.includes('sk_live_abc123xyz789secret'),
        'Raw secret found in request body!'
      );
      assert.ok(
        bodyStr.includes('sk_live_***'),
        'Masked value should be present'
      );
    }
  });

  it('should only send masked values for secrets', async () => {
    capturedRequests = [];
    const findings = [
      {
        file: 'config.js',
        line: 5,
        type: 'PRIVATE_KEY',
        match: '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...',
        redacted: '-----BEGIN RSA PRIVATE KEY-----\n***'
      }
    ];

    await triageFindings(findings, {
      apiKey: 'test-key',
      scanRoot: __dirname
    });

    for (const req of capturedRequests) {
      const bodyStr = JSON.stringify(req.body);
      assert.ok(
        !bodyStr.includes('MIIEpAIBAAKCAQEA'),
        'Raw private key fragment found in request!'
      );
      assert.ok(
        bodyStr.includes('***'),
        'Masked indicator should be present'
      );
    }
  });

  it('should send dependency metadata without secrets', async () => {
    capturedRequests = [];
    
    // Clear cache to ensure fresh request
    const cache = new TriageCache('.shrine-cache/triage');
    await cache.clear();
    
    const findings = [
      {
        package: 'lodash',
        version: '4.17.20',
        type: 'outdated',
        severity: 'high'
      }
    ];

    await triageFindings(findings, {
      apiKey: 'test-key'
    });

    assert.ok(capturedRequests.length > 0, 'Should have made at least one request');
    const bodyStr = JSON.stringify(capturedRequests[0].body);
    assert.ok(bodyStr.includes('lodash'), 'Package name should be present');
    assert.ok(bodyStr.includes('4.17.20'), 'Version should be present');
    assert.ok(bodyStr.includes('high'), 'Severity should be present');
  });

  it('should use correct provider based on env var', () => {
    const mistral = createProvider('mistral', 'key1', 'model1');
    assert.equal(mistral.constructor.name, 'MistralProvider');
    assert.equal(mistral.apiKey, 'key1');
    assert.equal(mistral.model, 'model1');

    const openrouter = createProvider('openrouter', 'key2', 'model2');
    assert.equal(openrouter.constructor.name, 'OpenRouterProvider');

    const groq = createProvider('groq', 'key3', 'model3');
    assert.equal(groq.constructor.name, 'GroqProvider');
  });

  it('should generate consistent cache keys', () => {
    const items1 = [
      { file: 'a.js', line: 1, type: 'API_KEY', match: '***' }
    ];
    const items2 = [
      { file: 'a.js', line: 1, type: 'API_KEY', match: '***' }
    ];
    
    const key1 = generateCacheKey(items1);
    const key2 = generateCacheKey(items2);
    
    assert.equal(key1, key2, 'Cache keys should be identical for same items');
  });

  it('should not include raw secrets in cache key generation', () => {
    const items = [
      { file: 'test.js', line: 1, type: 'SECRET', match: 'sk_live_***' }
    ];
    
    const key = generateCacheKey(items);
    
    // The key should be a hash, not contain the actual match
    assert.ok(key.length === 64, 'Should be SHA256 hash (64 hex chars)');
    assert.ok(/^[a-f0-9]+$/.test(key), 'Should be hexadecimal');
  });

  it('should fallback gracefully on provider failure', async () => {
    // Override fetch to simulate failure
    const originalFetch = global.fetch;
    global.fetch = async () => {
      throw new Error('Network failure');
    };

    const findings = [
      {
        file: 'test.js',
        line: 1,
        type: 'API_KEY',
        match: 'sk_test_***',
        redacted: 'sk_test_***'
      }
    ];

    const result = await triageFindings(findings, {
      apiKey: 'test-key',
      scanRoot: __dirname
    });

    // Should mark as important on failure
    assert.equal(result[0].triage, 'important');
    
    // Restore
    global.fetch = originalFetch;
  });

  it('should skip triage and warn when no API key provided', async () => {
    // Save original env
    const originalKey = process.env.SHRINE_TRIAGE_KEY;
    const originalMistralKey = process.env.MISTRAL_API_KEY;
    
    delete process.env.SHRINE_TRIAGE_KEY;
    delete process.env.MISTRAL_API_KEY;

    const findings = [
      {
        file: 'test.js',
        line: 1,
        type: 'API_KEY',
        match: 'sk_test_***',
        redacted: 'sk_test_***'
      }
    ];

    const result = await triageFindings(findings, {
      scanRoot: __dirname
    });

    // Should mark as skipped when no key
    assert.equal(result[0].triage, 'skipped');
    assert.equal(result.length, 1);
    
    // Restore
    if (originalKey) process.env.SHRINE_TRIAGE_KEY = originalKey;
    if (originalMistralKey) process.env.MISTRAL_API_KEY = originalMistralKey;
  });

  it('should skip triage for non-mistral provider without SHRINE_TRIAGE_KEY', async () => {
    const originalKey = process.env.SHRINE_TRIAGE_KEY;
    const originalProvider = process.env.SHRINE_TRIAGE_PROVIDER;
    
    delete process.env.SHRINE_TRIAGE_KEY;
    process.env.SHRINE_TRIAGE_PROVIDER = 'groq';

    const findings = [
      {
        file: 'test.js',
        line: 1,
        type: 'TOKEN',
        match: 'xoxb-***',
        redacted: 'xoxb-***'
      }
    ];

    const result = await triageFindings(findings, {
      scanRoot: __dirname
    });

    assert.equal(result[0].triage, 'skipped');
    
    // Restore
    if (originalKey) process.env.SHRINE_TRIAGE_KEY = originalKey;
    if (originalProvider) process.env.SHRINE_TRIAGE_PROVIDER = originalProvider;
    else delete process.env.SHRINE_TRIAGE_PROVIDER;
  });

  it('should cache verdicts correctly', async () => {
    const cache = new TriageCache('.shrine-cache/triage-test');
    const verdicts = [{ id: 1, verdict: 'noise' }];
    const key = 'test-key-123';

    await cache.set(key, verdicts);
    const retrieved = await cache.get(key);

    assert.deepEqual(retrieved, verdicts);
  });

  it('should expire cache after 24 hours', async () => {
    const cache = new TriageCache('.shrine-cache/triage-test');
    const key = 'expire-test';
    
    // Write a cache entry with old timestamp
    await cache.ensureCacheDir();
    const cacheFile = path.join(cache.cacheDir, `${key}.json`);
    const oldData = {
      timestamp: Date.now() - (25 * 60 * 60 * 1000), // 25 hours ago
      verdicts: [{ id: 1, verdict: 'important' }]
    };
    await fs.writeFile(cacheFile, JSON.stringify(oldData), 'utf-8');

    // Try to retrieve - should return null (expired)
    const result = await cache.get(key);
    assert.equal(result, null);
  });
});

describe('Secret Masking Verification', () => {
  it('should verify all secret patterns are masked before sending', async () => {
    capturedRequests = [];

    const secretPatterns = [
      'ghp_1234567890abcdefghijklmnopqrst',
      'sk_live_51234567890abcdefghijklmnop',
      'AIzaSyD1234567890abcdefghijklmnopqrs',
      'xoxb-1234567890-1234567890-abcdefghijklmnop'
    ];

    const findings = secretPatterns.map((secret, i) => ({
      file: `file${i}.js`,
      line: 1,
      type: 'SECRET',
      match: secret,
      redacted: secret.slice(0, 8) + '***'
    }));

    await triageFindings(findings, {
      apiKey: 'test-key',
      scanRoot: __dirname
    });

    // Verify none of the raw secrets appear in any request
    for (const req of capturedRequests) {
      const bodyStr = JSON.stringify(req.body);
      for (const secret of secretPatterns) {
        assert.ok(
          !bodyStr.includes(secret),
          `Raw secret ${secret} found in request body!`
        );
      }
    }
  });
});
