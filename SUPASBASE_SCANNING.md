# Supabase Database and Storage Scanning

This document explains how to use the Supabase scanning functionality added to the shrine CLI tool.

## Overview

The shrine CLI now includes comprehensive scanning capabilities for Supabase database and storage configurations to detect common misconfigurations:

1. **RLS (Row Level Security) Misconfiguration Scanner**:
   - Detects tables with RLS disabled
   - Identifies tables with RLS enabled but no policies
   - Flags overly permissive RLS policies
   - **NEW (Day 6)**: Performs negative-identity testing to verify RLS actually blocks anonymous access

2. **Storage Bucket Exposure Scanner**:
   - Detects publicly accessible storage buckets

3. **SECURITY DEFINER Leak Detector**:
   - Identifies functions that run with elevated privileges and may bypass RLS

4. **Auth Configuration Checker**:
   - Provides reminders for manual auth config review (JWT expiry, email confirmation, etc.)

## Setup Requirements

To use the Supabase scanning features, you need:

1. A Supabase project (free tier available at [supabase.com](https://supabase.com))
2. The project's URL and **service_role** API key (required for admin-level database access)
3. *Optional but recommended*: The project's **anon/public** API key (for negative-identity testing)
4. Execution of the provided SQL setup file in your Supabase project

## Getting Supabase Credentials

1. Create a project at [supabase.com](https://supabase.com)
2. Navigate to Project Settings → API
3. Copy the:
   - **Project URL** (found under "Project API keys")
   - **service_role** API key (for admin operations - required)
   - **anon public** API key (for negative-identity testing - optional but recommended)

## SQL Setup Required

The Supabase scanners require custom PostgreSQL functions to be installed in your database. These functions are not available by default in Supabase.

### Manual Setup

Run the following SQL in your Supabase SQL editor (found in the Supabase dashboard):

```sql
-- Create function to check RLS status for all tables
CREATE OR REPLACE FUNCTION get_tables_rls_status()
RETURNS TABLE (
    schemaname text,
    tablename text,
    rls_enabled boolean,
    row_security text
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        n.nspname AS schemaname,
        c.relname AS tablename,
        c.relrowsecurity AS rls_enabled,
        CASE 
            WHEN c.relrowsecurity THEN 'ENABLED' 
            ELSE 'DISABLED' 
        END AS row_security
    FROM pg_class c
    LEFT JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relkind = 'r'  -- Only tables
      AND n.nspname NOT IN ('pg_catalog', 'information_schema')
      AND n.nspname NOT LIKE 'pg_%'
      AND n.nspname NOT LIKE 'supabase_%'
      AND n.nspname NOT IN ('storage', 'auth', 'graphql_public')
    ORDER BY n.nspname, c.relname;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function to check policies for a specific table
CREATE OR REPLACE FUNCTION get_table_policies(schema_name text, table_name text)
RETURNS TABLE (
    policyname text,
    permissive boolean,
    roles text[],
    command text,
    qual text,
    with_check text
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        pol.policyname,
        CASE 
            WHEN pol.qual IS NULL OR pol.qual = '' THEN true 
            ELSE false 
        END AS permissive,
        array_agg(DISTINCT pol.roles) AS roles,
        pol.cmd AS command,
        pol.qual,
        pol.with_check
    FROM pg_policy pol
    JOIN pg_class c ON pol.polrelid = c.oid
    JOIN pg_namespace n ON c.relnamespace = n.oid
    WHERE n.nspname = schema_name
      AND c.relname = table_name
    GROUP BY pol.policyname, pol.qual, pol.with_check, pol.cmd;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant public access to these functions (required for the CLI to call them)
GRANT EXECUTE ON FUNCTION get_tables_rls_status() TO public;
GRANT EXECUTE ON FUNCTION get_table_policies(text, text) TO public;
```

### Alternative: Using the Provided SQL File (Recommended)

1. Navigate to the `sql/` directory in your shrine project
2. Open `setup_rls_check_function.sql`
3. Copy the contents
4. Paste into the Supabase SQL editor and run

**Note**: The SQL setup file now includes the `get_security_definer_functions()` function for detecting SECURITY DEFINER functions. If you previously ran an older version of the setup, you should re-run it to get the latest functions.

## Usage

Once you have your Supabase credentials and have executed the SQL setup:

### Basic Usage (Service Role Key Only)

```bash
# Using environment variables (recommended for security)
export SUPABASE_URL="your-project-url"
export SUPABASE_SERVICE_ROLE_KEY="your-service-role-key"
shrine scan --supabase /path/to/scan

# Or using CLI flags (less secure, visible in process list)
shrine scan --supabase --supabase-url "your-project-url" --supabase-key "your-service-role-key" /path/to/scan
```

### Enhanced Usage with Negative-Identity Testing (Recommended)

To enable **negative-identity testing** (which actually attempts to access tables as an anonymous user to verify RLS is working), provide the anon key:

```bash
# Using environment variables
export SUPABASE_URL="your-project-url"
export SUPABASE_SERVICE_ROLE_KEY="your-service-role-key"
export SUPABASE_ANON_KEY="your-anon-public-key"
shrine scan --supabase /path/to/scan

# Or using CLI flags
shrine scan --supabase \
  --supabase-url "your-project-url" \
  --supabase-key "your-service-role-key" \
  --supabase-anon-key "your-anon-key" \
  /path/to/scan
```

### Advanced: Write Testing (Use with Caution)

By default, negative-identity testing only performs **READ tests** (safe, non-destructive). To also test if anonymous users can **WRITE** to tables (temporarily inserts and then deletes a test record), use the `--allow-write-test` flag:

```bash
shrine scan --supabase \
  --supabase-anon-key "your-anon-key" \
  --allow-write-test \
  /path/to/scan
```

**⚠️ Warning**: Write tests modify data temporarily. Only use this on test/development projects, not production databases.

### What Gets Scanned

The Supabase scanner will:
- Connect to your Supabase project using the provided credentials
- Check all user-created tables for RLS configuration issues
- **NEW**: If anon key provided, attempt to read from each table as an anonymous user to verify RLS enforcement
- **NEW**: If `--allow-write-test` flag provided, attempt to write to tables as anonymous user
- **NEW**: Check for SECURITY DEFINER functions that may bypass RLS
- Scan storage buckets for public access settings
- **NEW**: Provide reminders for manual auth configuration review
- Report findings in the same format as other shrine scanners

## Interpreting Results

Findings will be displayed with severity levels:
- **CRITICAL**: Immediate security threats (e.g., anonymous users can write to tables)
- **HIGH**: Critical misconfigurations (e.g., tables with RLS completely disabled, or RLS present but bypassed)
- **MEDIUM**: Important issues that should be addressed (e.g., public storage buckets, SECURITY DEFINER functions)
- **INFO**: Informational findings (e.g., reminders for manual auth config review)

Each finding includes:
- Type of issue detected
- Affected resource (table name, bucket name, function name, etc.)
- Detailed description
- Remediation guidance

### New Finding Types (Day 6)

1. **RLS Bypass - Anon Read** (HIGH):
   - Anonymous users can successfully read from a table despite RLS being enabled
   - Indicates RLS policies are not properly configured to block unauthorized access
   - Example: Policy uses `(true)` instead of `auth.uid() = user_id`

2. **RLS Bypass - Anon Write** (CRITICAL):
   - Anonymous users can insert data into a table
   - Severe security issue requiring immediate attention
   - Only detected when `--allow-write-test` flag is used

3. **SECURITY DEFINER Function** (MEDIUM):
   - A function runs with elevated privileges and may bypass RLS
   - Review function code to ensure proper access checks are in place
   - Common pattern: functions that expose data without checking `auth.uid()`

4. **Auth Config Review Needed** (INFO):
   - Reminder to manually review authentication settings in Supabase Dashboard
   - Check: email confirmation, JWT expiry, password requirements

## Error Handling

If the scanner encounters issues:

1. **Missing Credentials**: 
   - Error: "Supabase URL and key are required for scanning"
   - Solution: Provide credentials via environment variables or CLI flags

2. **Connection Failed**:
   - Error: "Failed to connect to Supabase: [details]"
   - Solution: Verify your URL and key are correct and your project is active

3. **Missing SQL Functions**:
   - Error: "Supabase scanning requires custom SQL functions to be installed in your database"
   - Solution: Run the SQL setup file in your Supabase project's SQL editor

4. **Insufficient Permissions**:
   - Error: Related to permission denied when calling functions
   - Solution: Ensure the GRANT statements in the SQL setup were executed

5. **Anon Key Not Provided**:
   - Not an error: Negative-identity testing will be skipped
   - Solution: Provide `--supabase-anon-key` to enable this test

## Limitations

1. The scanner can only access tables in the public schema and other non-system schemas
2. Requires execution of custom SQL functions in your Supabase database
3. Only scans for specific misconfiguration patterns (not exhaustive security audit)
4. Storage scanner currently only checks public bucket settings, not object-level permissions
5. Negative-identity testing simulates anonymous access but cannot test authenticated user scenarios
6. Write tests (`--allow-write-test`) temporarily modify data and should only be used on non-production databases
7. Auth configuration checks require manual dashboard review (not fully automated)

## Security Notes

- The shrine CLI only performs READ operations on your Supabase database
- No data is modified or deleted during scanning
- Credentials are used solely to establish a connection for querying metadata
- Consider using a separate Supabase project for testing if concerned about exposing production credentials