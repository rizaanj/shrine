#!/usr/bin/env node

const { Command } = require('commander');
const { scanCommand } = require('../lib/commands/scan');
const { loginCommand, logoutCommand } = require('../lib/commands/login');
const { autofixCommand } = require('../lib/commands/autofix');

const program = new Command();

program
  .name('shrine')
  .description('CLI tool to scan repositories for exposed secrets and API keys')
  .version('1.0.0');

// Login command
program
  .command('login <access-key>')
  .description('Authenticate with your Shrine access key')
  .option('--backend-url <url>', 'Shrine backend URL (or set SHRINE_BACKEND_URL env var)')
  .option('--backend-anon-key <key>', 'Shrine backend anon key (or set SHRINE_BACKEND_ANON_KEY env var)')
  .action(loginCommand);

// Logout command
program
  .command('logout')
  .description('Remove stored access key')
  .action(logoutCommand);

// Scan command
program
  .command('scan')
  .description('Scan a directory for exposed secrets')
  .option('--path <dir>', 'Directory to scan', process.cwd())
  .option('--verbose', 'Enable verbose output', false)
  .option('--include-tests', 'Include test directories in scan', false)
  .option('--respect-gitignore', 'Only scan files not ignored by .gitignore (default scans everything)', false)
  .option('--full', 'No-op: full coverage is already the default', false)
  .option('--history', 'Scan git commit history for secrets', false)
  .option('--depth <n>', 'Number of commits to scan in history (default: 100)', parseInt)
  .option('--full-history', 'Scan entire git history (no commit limit)', false)
  .option('--deep-history', 'Scan reflog and orphaned commits for secrets hidden by force-pushes', false)
  .option('--entropy', 'Enable entropy-based detection for unknown secret patterns', false)
  .option('--no-ast', 'Disable AST-based parsing for JS/TS files (fall back to regex)', false)
  .option('--supabase', 'Scan Supabase database for RLS and storage misconfigurations', false)
  .option('--supabase-url <url>', 'Supabase project URL (or set SUPABASE_URL env var)')
  .option('--supabase-key <key>', 'Supabase service role key (or set SUPABASE_SERVICE_ROLE_KEY env var)')
  .option('--supabase-anon-key <key>', 'Supabase anon/public key for negative-identity testing (or set SUPABASE_ANON_KEY env var)')
  .option('--allow-write-test', 'Allow write tests during negative-identity testing (modifies data temporarily)', false)
  .option('--sqli <url>', 'Test for SQL injection using sqlmap (requires sqlmap installation)')
  .option('--sqli-level <n>', 'Level of tests to perform (1-5, default 1)', parseInt, 1)
  .option('--sqli-risk <n>', 'Risk of tests to perform (1-3, default 1)', parseInt, 1)
  .option('--skip-auth', 'Skip authentication check (for testing)', false)
  .option('--fix-prompts', 'Generate fix prompts for each finding', false)
  .option('--triage', 'Triage findings with Codestral (needs MISTRAL_API_KEY or --triage-key); hides noise', false)
  .option('--triage-key <key>', 'Codestral/Mistral API key (or set MISTRAL_API_KEY env var)')
  .option('--all', 'Show all findings including triaged noise (with --triage)', false)
  .option('--no-deps', 'Skip dependency audit (OSV, typosquat, install scripts)', false)
  .action(scanCommand);

// Review command (comprehensive scan with interactive review)
program
  .command('review')
  .description('Scan everything and review fix prompts interactively (does not edit files)')
  .option('--path <dir>', 'Directory to scan', process.cwd())
  .option('--verbose', 'Enable verbose output', false)
  .option('--include-tests', 'Include test directories in scan', false)
  .option('--respect-gitignore', 'Only scan files not ignored by .gitignore (default scans everything)', false)
  .option('--entropy', 'Enable entropy-based detection for unknown secret patterns', false)
  .option('--no-ast', 'Disable AST-based parsing for JS/TS files (fall back to regex)', false)
  .option('--supabase-url <url>', 'Supabase project URL (or set SUPABASE_URL env var)')
  .option('--supabase-key <key>', 'Supabase service role key (or set SUPABASE_SERVICE_ROLE_KEY env var)')
  .option('--supabase-anon-key <key>', 'Supabase anon/public key for negative-identity testing (or set SUPABASE_ANON_KEY env var)')
  .option('--allow-write-test', 'Allow write tests during negative-identity testing (modifies data temporarily)', false)
  .option('--skip-auth', 'Skip authentication check (for testing)', false)
  .action(autofixCommand);

program.parse(process.argv);
