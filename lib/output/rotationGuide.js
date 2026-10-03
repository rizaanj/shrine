function getRotationSteps(findingType) {
  switch (findingType) {
    case 'Generic API Key':
      return [
        'Revoke the old API key in the dashboard',
        'Generate a new API key',
        'Update the API key in your environment variables',
        'Purge the old API key from git history using BFG or filter-repo',
        'Rotate the API key in any downstream services'
      ];
    case 'Supabase':
      return [
        'Revoke the old Supabase key in the dashboard',
        'Generate a new Supabase key',
        'Update the Supabase key in your environment variables',
        'Purge the old Supabase key from git history using BFG or filter-repo',
        'Rotate the Supabase key in any downstream services'
      ];
    case 'Stripe':
      return [
        'Revoke the old Stripe key in the dashboard',
        'Generate a new Stripe key',
        'Update the Stripe key in your environment variables',
        'Purge the old Stripe key from git history using BFG or filter-repo',
        'Rotate the Stripe key in any downstream services'
      ];
    case 'OpenAI':
      return [
        'Revoke the old OpenAI key in the dashboard',
        'Generate a new OpenAI key',
        'Update the OpenAI key in your environment variables',
        'Purge the old OpenAI key from git history using BFG or filter-repo',
        'Rotate the OpenAI key in any downstream services'
      ];
    case 'GitHub':
      return [
        'Revoke the old GitHub token in the dashboard',
        'Generate a new GitHub token',
        'Update the GitHub token in your environment variables',
        'Purge the old GitHub token from git history using BFG or filter-repo',
        'Rotate the GitHub token in any downstream services'
      ];
    default:
      return [];
  }
}
module.exports = { getRotationSteps };
