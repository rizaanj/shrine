-- Shrine Security Scanner - Supabase RLS Check Functions
-- Run this SQL in your Supabase SQL Editor to enable the RLS scanner

-- Function to get all tables in public schema with their RLS status
CREATE OR REPLACE FUNCTION get_tables_rls_status()
RETURNS TABLE (
  table_name text,
  rls_enabled boolean,
  policy_count bigint
) 
SECURITY DEFINER
LANGUAGE plpgsql
AS $$
BEGIN
  RETURN QUERY
  SELECT 
    t.tablename::text,
    COALESCE(c.relrowsecurity, false) as rls_enabled,
    COUNT(p.policyname) as policy_count
  FROM pg_tables t
  LEFT JOIN pg_class c ON c.relname = t.tablename 
    AND c.relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')
  LEFT JOIN pg_policies p ON p.schemaname = t.schemaname 
    AND p.tablename = t.tablename
  WHERE t.schemaname = 'public'
  GROUP BY t.tablename, c.relrowsecurity
  ORDER BY t.tablename;
END;
$$;

-- Function to get policies for a specific table
CREATE OR REPLACE FUNCTION get_table_policies(table_name text)
RETURNS TABLE (
  policyname text,
  cmd text,
  qual text,
  with_check text
)
SECURITY DEFINER
LANGUAGE plpgsql
AS $$
BEGIN
  RETURN QUERY
  SELECT 
    p.policyname::text,
    p.cmd::text,
    p.qual::text,
    p.with_check::text
  FROM pg_policies p
  WHERE p.schemaname = 'public'
    AND p.tablename = table_name
  ORDER BY p.policyname;
END;
$$;

-- Function to get SECURITY DEFINER functions in public schema
CREATE OR REPLACE FUNCTION get_security_definer_functions()
RETURNS TABLE (
  function_name text,
  argument_types text
)
SECURITY DEFINER
LANGUAGE plpgsql
AS $$
BEGIN
  RETURN QUERY
  SELECT 
    p.proname::text AS function_name,
    pg_get_function_arguments(p.oid)::text AS argument_types
  FROM pg_proc p
  JOIN pg_namespace n ON p.pronamespace = n.oid
  WHERE n.nspname = 'public'
    AND p.prosecdef = true
    AND p.proname NOT IN ('get_tables_rls_status', 'get_table_policies', 'get_security_definer_functions', 'get_table_columns')
  ORDER BY p.proname;
END;
$$;

-- Function to get column information for a table
CREATE OR REPLACE FUNCTION get_table_columns(table_name_param text)
RETURNS TABLE (
  column_name text,
  data_type text,
  is_nullable text,
  column_default text
)
SECURITY DEFINER
LANGUAGE plpgsql
AS $$
BEGIN
  RETURN QUERY
  SELECT 
    c.column_name::text,
    c.data_type::text,
    c.is_nullable::text,
    c.column_default::text
  FROM information_schema.columns c
  WHERE c.table_schema = 'public'
    AND c.table_name = table_name_param
  ORDER BY c.ordinal_position;
END;
$$;

-- Grant execute permissions to service_role
GRANT EXECUTE ON FUNCTION get_tables_rls_status() TO service_role;
GRANT EXECUTE ON FUNCTION get_table_policies(text) TO service_role;
GRANT EXECUTE ON FUNCTION get_security_definer_functions() TO service_role;
GRANT EXECUTE ON FUNCTION get_table_columns(text) TO service_role;

-- Success message
DO $$
BEGIN
  RAISE NOTICE 'Shrine RLS check functions created successfully!';
  RAISE NOTICE 'You can now run: shrine scan --supabase';
END $$;
