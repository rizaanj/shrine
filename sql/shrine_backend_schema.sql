-- Shrine Backend Schema
-- This is for Shrine's own user accounts and beta access tracking
-- Separate from any test-target Supabase projects

-- Create beta_access table
CREATE TABLE IF NOT EXISTS public.beta_access (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  access_key TEXT UNIQUE NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  is_active BOOLEAN DEFAULT TRUE,
  tier TEXT DEFAULT 'free_beta'
);

-- Enable Row Level Security
ALTER TABLE public.beta_access ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only read their own beta_access row
CREATE POLICY "Users can read own beta_access"
  ON public.beta_access
  FOR SELECT
  USING (auth.uid() = id);

-- Policy: Allow service role to insert (for the trigger)
CREATE POLICY "Service role can insert beta_access"
  ON public.beta_access
  FOR INSERT
  WITH CHECK (true);

-- Secure RPC function for validating access keys
-- Only returns is_active and tier, no user IDs or sensitive data
CREATE OR REPLACE FUNCTION public.validate_access_key(key TEXT)
RETURNS TABLE(is_active BOOLEAN, tier TEXT) AS $$
BEGIN
  RETURN QUERY
  SELECT ba.is_active, ba.tier
  FROM public.beta_access ba
  WHERE ba.access_key = key
  LIMIT 1;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

-- Grant execute permission to anonymous users
GRANT EXECUTE ON FUNCTION public.validate_access_key(TEXT) TO anon;

-- Function to generate a shorter, more readable access key
-- Format: shrine_xxxxxxxxxxxxxxxxxxxx (24 chars total)
CREATE OR REPLACE FUNCTION generate_access_key()
RETURNS TEXT AS $$
DECLARE
  chars TEXT := 'abcdefghijklmnopqrstuvwxyz0123456789';
  result TEXT := 'shrine_';
  i INTEGER;
BEGIN
  FOR i IN 1..16 LOOP
    result := result || substr(chars, floor(random() * length(chars) + 1)::integer, 1);
  END LOOP;
  RETURN result;
END;
$$ LANGUAGE plpgsql;

-- Function to create beta_access row on user signup
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
DECLARE
  chars TEXT := 'abcdefghijklmnopqrstuvwxyz0123456789';
  new_key TEXT := 'shrine_';
  i INTEGER;
BEGIN
  FOR i IN 1..16 LOOP
    new_key := new_key || substr(chars, floor(random() * length(chars) + 1)::integer, 1);
  END LOOP;
  
  INSERT INTO public.beta_access (id, access_key)
  VALUES (NEW.id, new_key);
  
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

-- Trigger to automatically create beta_access row when user signs up
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW
  EXECUTE FUNCTION handle_new_user();

-- Index for faster access_key lookups
CREATE INDEX IF NOT EXISTS idx_beta_access_key ON public.beta_access(access_key);

-- Grant necessary permissions
GRANT USAGE ON SCHEMA public TO anon, authenticated;
GRANT SELECT ON public.beta_access TO anon, authenticated;
