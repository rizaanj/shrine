const fg = require('fast-glob');
const fs = require('fs').promises;
const path = require('path');

/**
 * Scan for exposed API endpoints without authentication
 */
async function scanApiEndpoints(targetPath, options = {}) {
  const findings = [];
  const verbose = options.verbose || false;
  const apiUrl = options.apiUrl || null;

  if (verbose) {
    console.log('\n=== API Endpoint Security Scan ===');
  }

  try {
    // Step 1: Discover route files
    const routeFiles = await discoverRouteFiles(targetPath, verbose);
    
    if (routeFiles.length === 0) {
      if (verbose) {
        console.log('No API route files found');
      }
      return findings;
    }

    if (verbose) {
      console.log(`Found ${routeFiles.length} potential API route files`);
    }

    // Step 2: Parse routes and check for auth
    const routes = [];
    for (const file of routeFiles) {
      const fileRoutes = await parseRouteFile(file, targetPath, findings, verbose);
      routes.push(...fileRoutes);
    }

    if (verbose) {
      console.log(`Discovered ${routes.length} API routes`);
    }

    // Step 3: Check for global rate limiting
    if (routes.length > 0) {
      await checkRateLimiting(targetPath, findings, verbose);
    }

    // Step 4: Optional live probing
    if (apiUrl && routes.length > 0) {
      const urlHost = new URL(apiUrl).host;
      if (verbose) {
        console.log(`\nLive API testing on owner-authorized URL: ${urlHost}`);
      }
      await probeRoutes(apiUrl, routes.slice(0, 10), findings, verbose);
    }

  } catch (error) {
    if (verbose) {
      console.log(`API scanner error: ${error.message}`);
    }
  }

  return findings;
}

/**
 * Discover API route files using fast-glob
 */
async function discoverRouteFiles(targetPath, verbose) {
  const patterns = [
    '**/pages/api/**/*.{js,jsx,ts,tsx}',
    '**/app/api/**/route.{js,ts,jsx,tsx}',
    '**/src/pages/api/**/*',
    '**/src/app/api/**/*',
    '**/api/**/*.{js,ts}',
    '**/routes/**/*.{js,ts}'
  ];

  const ignore = [
    '**/node_modules/**',
    '**/.git/**',
    '**/dist/**',
    '**/build/**',
    '**/.next/**'
  ];

  try {
    const files = await fg(patterns, {
      cwd: targetPath,
      absolute: true,
      ignore,
      onlyFiles: true
    });

    return files;
  } catch (error) {
    if (verbose) {
      console.log(`Route discovery error: ${error.message}`);
    }
    return [];
  }
}

/**
 * Parse route file and check for authentication
 */
async function parseRouteFile(filePath, targetPath, findings, verbose) {
  const routes = [];

  try {
    const content = await fs.readFile(filePath, 'utf-8');
    const lines = content.split('\n').slice(0, 500); // First 500 lines only

    // Convert file path to route path
    const routePath = filePathToRoute(filePath, targetPath);
    
    if (!routePath) {
      return routes;
    }

    // Extract defined routes from code
    const definedRoutes = extractRoutesFromCode(content, routePath);
    
    if (definedRoutes.length === 0) {
      // Use file-based route
      definedRoutes.push({ path: routePath, line: 1 });
    }

    // Check each route for auth
    for (const route of definedRoutes) {
      routes.push(route.path);

      // Check for auth keywords around route definition
      const hasAuth = checkForAuth(lines, route.line, verbose);

      if (!hasAuth) {
        const isAdmin = /\/admin($|\/)/i.test(route.path);
        const severity = isAdmin ? 'critical' : 'high';
        const type = isAdmin ? 'Open Admin Route' : 'API Missing Auth';

        // Get evidence line (redacted)
        const evidenceLine = lines[route.line - 1] || '';
        const redacted = evidenceLine.slice(0, 100);

        findings.push({
          type,
          severity,
          file: path.relative(targetPath, filePath),
          line: route.line,
          route: route.path,
          message: `Route '${route.path}' appears to lack authentication checks`,
          evidence: redacted,
          remediation: `Add authentication middleware (e.g., verifyToken, requireAuth) before handling ${route.path}`
        });

        if (verbose) {
          console.log(`  ${severity.toUpperCase()}: ${route.path} - no auth detected`);
        }
      } else {
        if (verbose) {
          console.log(`  OK: ${route.path} - auth detected`);
        }
      }
    }

  } catch (error) {
    if (verbose) {
      console.log(`  Error parsing ${filePath}: ${error.message}`);
    }
  }

  return routes;
}

/**
 * Convert file path to API route path
 */
function filePathToRoute(filePath, targetPath) {
  const relative = path.relative(targetPath, filePath);
  const normalized = relative.replace(/\\/g, '/');

  // Next.js App Router: app/api/foo/route.js => /api/foo
  if (normalized.includes('/app/api/') || normalized.includes('app/api/')) {
    const match = normalized.match(/app\/api\/(.+)\/route\.[jt]sx?$/);
    if (match) {
      return `/api/${match[1]}`;
    }
  }

  // Next.js Pages: pages/api/foo.js => /api/foo
  if (normalized.includes('/pages/api/') || normalized.includes('pages/api/')) {
    const match = normalized.match(/pages\/api\/(.+)\.[jt]sx?$/);
    if (match) {
      return `/api/${match[1]}`;
    }
  }

  // Generic /api/: api/foo.js => /api/foo
  if (normalized.match(/^api\//)) {
    const match = normalized.match(/^api\/(.+)\.[jt]sx?$/);
    if (match) {
      return `/api/${match[1]}`;
    }
  }

  // Generic /routes/: routes/foo.js => /foo
  if (normalized.match(/routes\//)) {
    const match = normalized.match(/routes\/(.+)\.[jt]sx?$/);
    if (match) {
      return `/${match[1]}`;
    }
  }

  return null;
}

/**
 * Extract routes defined in code (Express/Fastify style)
 */
function extractRoutesFromCode(content, defaultPath) {
  const routes = [];
  const lines = content.split('\n');

  // Regex for app.get('/path'), router.post('/path'), etc.
  const routeRegex = /(app|router|server)\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]/g;

  let match;
  while ((match = routeRegex.exec(content)) !== null) {
    const routePath = match[3];
    
    // Find line number
    const lineNumber = content.substring(0, match.index).split('\n').length;
    
    // Check if in comment
    const line = lines[lineNumber - 1];
    if (isInComment(line, match.index - content.lastIndexOf('\n', match.index))) {
      continue;
    }

    routes.push({
      path: routePath.startsWith('/') ? routePath : `/${routePath}`,
      line: lineNumber
    });
  }

  return routes;
}

/**
 * Check if position is within a comment
 */
function isInComment(line, position) {
  const beforePos = line.substring(0, position);
  
  // Single-line comment
  if (beforePos.includes('//')) {
    return true;
  }
  
  // Multi-line comment (basic check)
  if (beforePos.includes('/*') && !beforePos.includes('*/')) {
    return true;
  }

  return false;
}

/**
 * Check for authentication keywords around route definition
 */
function checkForAuth(lines, routeLine, verbose) {
  const authKeywords = [
    'auth',
    'authenticate',
    'verifyToken',
    'requireAuth',
    'withAuth',
    'isAuthenticated',
    'middleware',
    'checkAuth',
    'clerk',
    'supabase.auth'
  ];

  // Check 20 lines around route definition
  const startLine = Math.max(0, routeLine - 20);
  const endLine = Math.min(lines.length, routeLine + 20);

  for (let i = startLine; i < endLine; i++) {
    const line = lines[i].toLowerCase();
    
    // Skip comments
    if (line.trim().startsWith('//') || line.trim().startsWith('*')) {
      continue;
    }

    for (const keyword of authKeywords) {
      if (line.includes(keyword.toLowerCase())) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Check for global rate limiting configuration
 */
async function checkRateLimiting(targetPath, findings, verbose) {
  const rateLimitKeywords = [
    'rateLimit',
    'rate-limit',
    'express-rate-limit',
    'throttle',
    'slow-down'
  ];

  try {
    const files = await fg(['**/*.{js,ts,json}'], {
      cwd: targetPath,
      absolute: true,
      ignore: ['**/node_modules/**', '**/.git/**', '**/dist/**', '**/build/**']
    });

    let found = false;
    for (const file of files) {
      try {
        const content = await fs.readFile(file, 'utf-8');
        for (const keyword of rateLimitKeywords) {
          if (content.includes(keyword)) {
            found = true;
            if (verbose) {
              console.log(`Rate limiting detected in ${path.relative(targetPath, file)}`);
            }
            break;
          }
        }
        if (found) break;
      } catch (err) {
        // Skip files that can't be read
      }
    }

    if (!found) {
      findings.push({
        type: 'No Rate Limiting',
        severity: 'medium',
        message: 'No rate limiting detected on API routes - vulnerable to brute force/abuse',
        remediation: 'Add express-rate-limit or Upstash/Vercel rate limiting'
      });

      if (verbose) {
        console.log('  WARNING: No rate limiting detected');
      }
    }

  } catch (error) {
    if (verbose) {
      console.log(`Rate limit check error: ${error.message}`);
    }
  }
}

/**
 * Probe routes with live GET requests (read-only)
 */
async function probeRoutes(apiUrl, routes, findings, verbose) {
  if (verbose) {
    console.log(`\nProbing ${routes.length} routes (read-only GET)...`);
  }

  const baseUrl = apiUrl.replace(/\/$/, '');

  for (const route of routes) {
    try {
      const url = `${baseUrl}${route}`;
      
      if (verbose) {
        console.log(`  Testing: ${route}`);
      }

      // Create abort signal with 5s timeout
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);

      const response = await fetch(url, {
        method: 'GET',
        signal: controller.signal,
        headers: {
          'User-Agent': 'Shrine-Security-Scanner/1.0'
        }
      });

      clearTimeout(timeoutId);

      // Check if response indicates unauthenticated access
      if (response.status === 200) {
        const bodyText = await response.text();
        
        // Only flag if body is not empty (avoid false positives on empty responses)
        if (bodyText && bodyText.trim().length > 0) {
          findings.push({
            type: 'API Anon Access',
            severity: 'high',
            route,
            evidence: {
              status: 200,
              bodyTruncated: bodyText.slice(0, 200)
            },
            message: `GET ${route} returned 200 without authentication`,
            remediation: `Add authentication checks to ${route} endpoint`
          });

          if (verbose) {
            console.log(`    ISSUE: 200 OK without auth`);
          }
        }
      } else if ([401, 403, 302].includes(response.status)) {
        if (verbose) {
          console.log(`    OK: ${response.status} (auth working)`);
        }
      } else {
        if (verbose) {
          console.log(`    ${response.status}`);
        }
      }

    } catch (error) {
      if (error.name === 'AbortError') {
        console.warn(`API probe skipped: ${route} - timeout`);
      } else {
        console.warn(`API probe skipped: ${route} - ${error.message}`);
      }
    }
  }
}

module.exports = {
  scanApiEndpoints
};
