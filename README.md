# Shrine

A CLI security scanner that detects exposed secrets, API keys, vulnerable code patterns, and access control issues in your repositories.

## Features

- **Secret Detection**: Scans for exposed API keys, tokens, database credentials, and private keys
- **Code Pattern Analysis**: Identifies XSS vulnerabilities, SQL injection risks, and unsafe code patterns
- **JWT Security**: Validates JWT tokens for security issues (none algorithm, missing expiration, exposed secrets)
- **Dependency Auditing**: Checks for outdated packages, typosquat risks, and malicious install scripts
- **Git History Scanning**: Searches commit history for secrets, including reflog and orphaned commits
- **Supabase Security**: Tests Row Level Security (RLS) policies and storage permissions
- **Access Control Testing**: Verifies whether one user can read another user's data (negative-identity testing)
- **SQL Injection Testing**: Integrates with sqlmap for automated SQLi detection
- **Auto-fix**: Generates and applies security fixes with interactive review

## Installation

```bash
npm install -g shrine-cli
```

Or install locally:

```bash
npm install shrine-cli
```

## Authentication

Get your access key at https://shrinecli.netlify.app/

```bash
shrine login <your-access-key>
```

## Usage

### Basic scan
```bash
shrine scan
```

### Scan with options
```bash
# Scan specific directory
shrine scan --path /path/to/project

# Include git history
shrine scan --history

# Scan all commits (may be slow)
shrine scan --full-history

# Enable entropy-based detection for unknown patterns
shrine scan --entropy

# Respect .gitignore
shrine scan --respect-gitignore
```

### Supabase security testing
```bash
# Test RLS policies and storage permissions
shrine scan --supabase \
  --supabase-url https://your-project.supabase.co \
  --supabase-key your-service-role-key \
  --supabase-anon-key your-anon-key

# Enable write tests (modifies data temporarily)
shrine scan --supabase --allow-write-test
```

**Note**: Supabase scanning includes negative-identity testing, which verifies that one user cannot read or modify another user's data. This ensures your RLS policies are correctly configured to prevent unauthorized access.

### SQL injection testing
```bash
shrine scan --sqli https://your-app.com --sqli-level 3 --sqli-risk 2
```

### Interactive fix review
```bash
# Review and apply fixes interactively
shrine review

# Auto-apply all fixes (use with caution)
shrine review --apply
```

### Monitor mode
```bash
# Continuous monitoring with staleness checks
shrine monitor --interval 60
```

### PR scanning
```bash
# Scan GitHub/GitLab PR and block merge on critical findings
shrine pr 123
```

### Advanced options
```bash
# Triage findings with AI (filters noise)
shrine scan --triage --triage-key your-mistral-api-key

# Skip dependency audit
shrine scan --no-deps

# Skip code pattern scan
shrine scan --no-code-scan

# Verbose output
shrine scan --verbose
```

## Configuration

Create a `.env` file in your project root:

```env
SHRINE_BACKEND_URL=
SHRINE_BACKEND_ANON_KEY=

# Optional: Triage API
MISTRAL_API_KEY=
SHRINE_TRIAGE_PROVIDER=mistral
SHRINE_TRIAGE_MODEL=codestral-latest
```

## Output

Shrine generates a security score (0-100) and detailed findings with:
- Secret type and location
- Severity level (critical, high, medium, low)
- Fix suggestions
- False positive detection via AI triage

## License

ISC
