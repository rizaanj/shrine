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
