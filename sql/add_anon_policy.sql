-- Add RLS policy to allow anonymous access key lookup
CREATE POLICY "Allow access key lookup"
  ON public.beta_access
  FOR SELECT
  TO anon
  USING (true);
