// Supabase configuration with hardcoded keys
const { createClient } = require('@supabase/supabase-js');

const supabaseUrl = 'https://xyzcompany.supabase.co';
const supabaseAnonKey = 'sbp_1234567890abcdefghijklmnopqrstuvwxyz12';
const supabaseServiceKey = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Inh5emNvbXBhbnkiLCJyb2xlIjoic2VydmljZV9yb2xlIiwiaWF0IjoxNjQwMDAwMDAwfQ.abcdefghijklmnopqrstuvwxyz123456';

const supabase = createClient(supabaseUrl, supabaseAnonKey);
const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey);

module.exports = { supabase, supabaseAdmin };
