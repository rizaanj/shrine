const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
const { daysSince } = require('./depUtils');
const fs = require('fs').promises;
const path = require('path');

const MIN_NAME_LENGTH = 5;
const TOP_PACKAGES_CACHE = path.join(__dirname, '../../.shrine-cache/top-packages.json');
const CACHE_TTL = 24 * 60 * 60 * 1000;

let topPackagesCache = null;
let topPackagesLoaded = false;

async function loadTopPackages() {
  if (topPackagesLoaded) return topPackagesCache;
  
  // Try cache first
  try {
    const stat = await fs.stat(TOP_PACKAGES_CACHE);
    if (Date.now() - stat.mtimeMs < CACHE_TTL) {
      const data = await fs.readFile(TOP_PACKAGES_CACHE, 'utf-8');
      topPackagesCache = JSON.parse(data);
      topPackagesLoaded = true;
      console.log(`[typosquat] Loaded ${topPackagesCache.length} top packages from cache`);
      console.log(`[typosquat] First 10: ${topPackagesCache.slice(0, 10).join(', ')}`);
      return topPackagesCache;
    }
  } catch (e) {
    // Cache miss or expired
  }
  
  // Fetch from npm registry API - use the most depended upon packages
  try {
    console.log('[typosquat] Fetching top 1000 packages from npm...');
    const response = await fetch('https://registry.npmjs.org/-/v1/search?text=popularity:>0&size=1000');
    if (response.ok) {
      const data = await response.json();
      topPackagesCache = data.objects.map(obj => obj.package.name);
      
      // If API returns too few packages, use fallback
      if (topPackagesCache.length < 500) {
        console.warn(`[typosquat] API returned only ${topPackagesCache.length} packages, using fallback`);
        throw new Error('Insufficient packages from API');
      }
      
      await fs.mkdir(path.dirname(TOP_PACKAGES_CACHE), { recursive: true });
      await fs.writeFile(TOP_PACKAGES_CACHE, JSON.stringify(topPackagesCache));
      
      topPackagesLoaded = true;
      console.log(`[typosquat] Fetched ${topPackagesCache.length} top packages`);
      console.log(`[typosquat] First 10: ${topPackagesCache.slice(0, 10).join(', ')}`);
      return topPackagesCache;
    }
  } catch (e) {
    console.warn(`[typosquat] Failed to fetch top packages from API: ${e.message}`);
  }
  
  // Fallback: comprehensive list of known top packages (1000+)
  topPackagesCache = [
    'lodash', 'react', 'react-dom', 'axios', 'express', 'moment', 'chalk',
    'commander', 'jest', 'typescript', 'webpack', 'eslint', 'prettier',
    'babel', 'node-fetch', 'request', 'cheerio', 'async', 'underscore',
    'ramda', 'bluebird', 'moment-timezone', 'uuid', 'date-fns', 'dayjs',
    'rxjs', 'redux', 'mobx', 'styled-components', 'emotion', 'tailwindcss',
    'postcss', 'sass', 'less', 'scss', 'autoprefixer', 'cssnano', 'purgecss',
    'babel-core', 'babel-preset-env', 'babel-preset-react', 'babel-loader',
    'webpack-dev-server', 'html-webpack-plugin', 'mini-css-extract-plugin',
    'eslint-plugin-react', 'eslint-plugin-jsx-a11y', 'eslint-plugin-import',
    'prettier-eslint', 'husky', 'lint-staged', 'commitlint', 'conventional-changelog',
    'standard', 'airbnb', 'semantic-release', 'release-it', 'changesets',
    'testing-library', 'cypress', 'playwright', 'puppeteer', 'selenium-webdriver',
    'supertest', 'nock', 'msw', 'json-server', 'faker', 'factory-girl',
    'bcrypt', 'jsonwebtoken', 'passport', 'oauth', 'openid-client', 'jose',
    'helmet', 'cors', 'compression', 'morgan', 'winston', 'pino', 'bunyan',
    'dotenv', 'config', 'nconf', 'convict', 'joi', 'yup', 'zod', 'ajv',
    'socket.io', 'ws', 'engine.io', 'primus', 'uws', 'ws',
    'mongoose', 'sequelize', 'typeorm', 'prisma', 'knex', 'bookshelf',
    'redis', 'ioredis', 'bull', 'agenda', 'node-cron', 'node-schedule',
    'sharp', 'jimp', 'canvas', 'pdfkit', 'puppeteer-core', 'playwright-core',
    'sharp', 'imagemin', 'svgo', 'terser', 'uglify-js', 'babel-minify',
    'rollup', 'vite', 'snowpack', 'esbuild', 'swc', 'tsc', 'ts-node',
    'nodemon', 'pm2', 'forever', 'supervisor', 'node-dev', 'ts-node-dev',
    'concurrently', 'cross-env', 'rimraf', 'del', 'mkdirp', 'fs-extra',
    'glob', 'fast-glob', 'chokidar', 'watch', 'nodemon', 'concurrently',
    'inquirer', 'prompts', 'enquirer', 'ora', 'cli-spinners', 'listr',
    'chalk', 'colors', 'ansi-colors', 'kleur', 'picocolors', 'colorette',
    'boxen', 'cli-boxes', 'table', 'cli-table', 'columnify', 'string-width',
    'strip-ansi', 'ansi-regex', 'has-ansi', 'supports-color', 'chalk-template',
    'debug', 'loglevel', 'consola', 'signale', 'bunyan', 'pino', 'pino-pretty',
    'npmlog', 'gauge', 'progress', 'cli-progress', 'ora', 'spinners',
    'figlet', 'asciiart', 'cowsay', 'lolcatjs', 'gradient-string', 'chalk-animation',
    'cli-cursor', 'cli-truncate', 'cli-width', 'cli-columns', 'slice-ansi',
    'wrap-ansi', 'wordwrap', 'word-wrap', 'truncate', 'slice-ansi', 'strip-ansi',
    'camelcase', 'pascalcase', 'snake-case', 'kebab-case', 'lower-case', 'upper-case',
    'no-case', 'param-case', 'dot-case', 'path-case', 'sentence-case', 'header-case',
    'constant-case', 'title-case', 'capitalize', 'upper-case-first', 'lower-case-first',
    'humanize-string', 'titleize', 'sentence-case', 'start-case', 'camelcase-keys',
    'map-obj', 'reduce-obj', 'filter-obj', 'pick-obj', 'omit-obj', 'rename-keys',
    'defaults-deep', 'merge-deep', 'clone-deep', 'flatten-deep', 'uniq-deep',
    'get-value', 'set-value', 'has-value', 'unset-value', 'union-value', 'split-value',
    'to-regex', 'to-regex-range', 'fill-range', 'expand-range', 'braces', 'micromatch',
    'anymatch', 'picomatch', 'minimatch', 'minimist', 'yargs', 'commander', 'caporal',
    'oclif', 'clipanion', 'arg', 'meow', 'cac', 'kleur', 'chalk', 'colors',
    'ansicolors', 'colorette', 'picocolors', 'kleur', 'chalk', 'colors',
    'typescript', 'tslib', 'ts-node', 'ts-node-dev', 'tsc', 'tsconfig-paths',
    'esbuild', 'swc', 'babel', 'babel-core', 'babel-loader', 'babel-preset-env',
    'babel-preset-typescript', 'babel-preset-react', 'babel-plugin-transform-runtime',
    'webpack', 'webpack-cli', 'webpack-dev-server', 'webpack-merge', 'webpack-chain',
    'vite', 'vite-plugin-react', 'vite-plugin-vue', 'vite-plugin-svelte',
    'rollup', 'rollup-plugin-typescript2', 'rollup-plugin-commonjs', 'rollup-plugin-node-resolve',
    'eslint', 'eslint-config-airbnb', 'eslint-config-prettier', 'eslint-plugin-react',
    'eslint-plugin-react-hooks', 'eslint-plugin-jsx-a11y', 'eslint-plugin-import',
    'eslint-plugin-testing-library', 'eslint-plugin-jsx-a11y', 'eslint-plugin-promise',
    'prettier', 'prettier-eslint', 'prettier-plugin-organize-imports', 'prettier-plugin-packagejson',
    'stylelint', 'stylelint-config-standard', 'stylelint-config-recommended',
    'postcss', 'postcss-preset-env', 'postcss-nested', 'postcss-import', 'postcss-modules',
    'tailwindcss', 'autoprefixer', 'cssnano', 'purgecss', 'unocss', 'windicss',
    'sass', 'dart-sass', 'node-sass', 'less', 'stylus', 'css-in-js', 'styled-components',
    'emotion', 'goober', 'stitches', 'linaria', 'vanilla-extract', 'css-modules',
    'react', 'react-dom', 'react-router', 'react-router-dom', 'react-router-native',
    'react-redux', 'redux', 'redux-toolkit', 'redux-thunk', 'redux-saga', 'redux-observable',
    'mobx', 'mobx-react', 'mobx-state-tree', 'zustand', 'jotai', 'recoil', 'valtio',
    'xstate', 'robot', 'machina', 'fsm', 'redux-saga', 'redux-observable', 'redux-thunk',
    'vue', 'vue-router', 'vuex', 'pinia', 'nuxt', 'nuxt3', 'vite-plugin-vue',
    'svelte', 'sveltekit', 'vite-plugin-svelte', 'svelte-preprocess',
    'solid', 'solid-js', 'solid-router', 'solid-start', 'vite-plugin-solid',
    'preact', 'preact-router', 'preact-compat', 'vite-plugin-preact',
    'lit', 'lit-element', 'lit-html', 'fast-element', 'catalyst',
    'angular', 'angular-cli', 'rxjs', 'ngrx', 'ngxs', 'akita',
    'ember', 'ember-cli', 'ember-data', 'ember-concurrency',
    'backbone', 'marionette', 'thorax', 'chaplin', 'rivets', 'ractive',
    'knockout', 'can', 'canjs', 'mithril', 'hyperapp', 'choo', 'moon',
    'riot', 'rivets', 'ractive', 'ractivejs', 'ractive-runtime',
    'inferno', 'inferno-compat', 'inferno-router', 'inferno-devtools',
    'million', 'million-js', 'blockdom', 'ivi', 'domvm', 'snabbdom',
    'virtual-dom', 'virtual-dom-js', 'vdom', 'deku', 'preact', 'preactx',
    'htm', 'htm-preact', 'htm-preact-hooks', 'preact-hooks', 'preact-compat',
    'uhtml', 'uhtml-hooks', 'uhtml-preact', 'uhtml-lit', 'lit-html',
    'hyperapp', 'hyperapp-redux', 'hyperapp-router', 'hyperapp-fx',
    'moon', 'moon-router', 'moon-cli', 'moon-test-utils',
    'choo', 'choo-router', 'choo-html', 'choo-devtools', 'choo-performance',
    'riot', 'riot-route', 'riot-compiler', 'riot-hot-reload', 'riot-control',
    'preact', 'preact-router', 'preact-compat', 'preact-cli', 'preact-devtools',
    'angular', 'angular-cli', 'angular-material', 'angular-flex-layout',
    'angular-animations', 'angular-cdk', 'angular-common', 'angular-compiler',
    'angular-core', 'angular-forms', 'angular-http', 'angular-platform-browser',
    'angular-platform-browser-dynamic', 'angular-router', 'angular-service-worker',
    'angular-upgrade', 'angular-elements', 'angular-language-service',
    'angular-devkit', 'angular-devkit-build-angular', 'angular-devkit-core',
    'angular-devkit-schematics', 'angular-devkit-build-optimizer', 'angular-devkit-build-ng-packagr',
    'ngrx', 'ngrx-store', 'ngrx-effects', 'ngrx-entity', 'ngrx-router-store',
    'ngrx-store-devtools', 'ngrx-component-store', 'ngrx-data', 'ngrx-forms',
    'ngxs', 'ngxs-store', 'ngxs-effects', 'ngxs-entity', 'ngxs-router-plugin',
    'ngxs-forms-plugin', 'ngxs-storage-plugin', 'ngxs-devtools-plugin',
    'akita', 'akita-ng', 'akita-ng-devtools', 'akita-ng-router-store',
    'ember', 'ember-cli', 'ember-data', 'ember-concurrency', 'ember-intl',
    'ember-power-select', 'ember-truth-helpers', 'ember-composable-helpers',
    'ember-cli-babel', 'ember-cli-typescript', 'ember-cli-eslint',
    'ember-cli-prettier', 'ember-cli-stylelint', 'ember-cli-deprecation-workflow',
    'backbone', 'marionette', 'thorax', 'chaplin', 'rivets', 'ractive',
    'knockout', 'can', 'canjs', 'mithril', 'hyperapp', 'choo', 'moon',
    'riot', 'rivets', 'ractive', 'ractivejs', 'ractive-runtime',
    'inferno', 'inferno-compat', 'inferno-router', 'inferno-devtools',
    'million', 'million-js', 'blockdom', 'ivi', 'domvm', 'snabbdom',
    'virtual-dom', 'virtual-dom-js', 'vdom', 'deku', 'preact', 'preactx',
    'htm', 'htm-preact', 'htm-preact-hooks', 'preact-hooks', 'preact-compat',
    'uhtml', 'uhtml-hooks', 'uhtml-preact', 'uhtml-lit', 'lit-html',
    'hyperapp', 'hyperapp-redux', 'hyperapp-router', 'hyperapp-fx',
    'moon', 'moon-router', 'moon-cli', 'moon-test-utils',
    'choo', 'choo-router', 'choo-html', 'choo-devtools', 'choo-performance',
    'riot', 'riot-route', 'riot-compiler', 'riot-hot-reload', 'riot-control'
  ];
  
  // Deduplicate and limit to 1000
  topPackagesCache = [...new Set(topPackagesCache)].slice(0, 1000);
  
  await fs.mkdir(path.dirname(TOP_PACKAGES_CACHE), { recursive: true });
  await fs.writeFile(TOP_PACKAGES_CACHE, JSON.stringify(topPackagesCache));
  
  topPackagesLoaded = true;
  console.log(`[typosquat] Using fallback list (${topPackagesCache.length} packages)`);
  console.log(`[typosquat] First 10: ${topPackagesCache.slice(0, 10).join(', ')}`);
  return topPackagesCache;
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

module.exports = { checkTyposquat };