-- Drop the anon policy that allows direct access
DROP POLICY IF EXISTS "Allow access key lookup" ON public.beta_access;

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
