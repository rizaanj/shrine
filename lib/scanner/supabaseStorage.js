const { createClient } = require('@supabase/supabase-js');

/**
 * Scan Supabase storage for public bucket exposure and misconfigurations
 */
async function scanStorage(supabaseUrl, serviceRoleKey, options = {}) {
  const findings = [];
  const verbose = options.verbose || false;
  
  try {
    // Create Supabase client with service role key (admin access)
    const supabase = createClient(supabaseUrl, serviceRoleKey);
    
    if (verbose) {
      console.log('Checking storage bucket configurations...');
    }
    
    // List all storage buckets
    const { data: buckets, error: bucketsError } = await supabase.storage.listBuckets();
    
    // Debug: Log raw response
    if (verbose) {
      console.log('Raw listBuckets() response:');
      console.log('  data:', JSON.stringify(buckets, null, 2));
      console.log('  error:', bucketsError);
    }
    
    if (bucketsError) {
      throw new Error(`Failed to list storage buckets: ${bucketsError.message}`);
    }
    
    if (!buckets || buckets.length === 0) {
      if (verbose) {
        console.log('No storage buckets found');
      }
      return findings;
    }
    
    if (verbose) {
      console.log(`Found ${buckets.length} storage bucket(s)`);
    }
    
    // Check each bucket's configuration
    for (const bucket of buckets) {
      const bucketName = bucket.name || bucket.id;
      const isPublic = bucket.public;
      
      if (verbose) {
        console.log(`\nChecking bucket: ${bucketName}`);
        console.log(`  Full bucket object:`, JSON.stringify(bucket, null, 2));
        console.log(`  bucket.public = ${isPublic}`);
        console.log(`  typeof bucket.public = ${typeof isPublic}`);
      }
      
      // Flag public buckets as medium severity
      if (isPublic) {
        if (verbose) {
          console.log(`  -> FLAGGING as public bucket (isPublic=${isPublic})`);
        }
        findings.push({
          type: 'Public Storage Bucket',
          severity: 'medium',
          bucket: bucketName,
          message: `Bucket '${bucketName}' is public — files are readable by anyone with the URL, verify this is intentional`,
          remediation: `Review bucket contents and set to private if sensitive files are stored. Use signed URLs for controlled access.`
        });
      } else {
        if (verbose) {
          console.log(`  -> Skipping (not public, isPublic=${isPublic})`);
        }
      }
      
      // Note: Bucket-level RLS policy checking would require additional SQL functions
      // For now, we only check the public flag which is the primary security concern
    }
    
  } catch (error) {
    throw new Error(`Storage scan failed: ${error.message}`);
  }
  
  return findings;
}

module.exports = {
  scanStorage
};
