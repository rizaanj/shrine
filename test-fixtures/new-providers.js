// Day 2 test fixtures - new provider patterns

// Stripe keys
const stripeConfig = {
  liveSK: 'sk_live_51HqF8xHH1234567890abcdefghijklmno',
  liveRK: 'rk_live_51HqF8xHH1234567890abcdefghijklmno',
  testSK: 'sk_test_51HqF8xHH1234567890abcdefghijklmno',
  testRK: 'rk_test_51HqF8xHH1234567890abcdefghijklmno'
};

// OpenAI keys
const OPENAI_API_KEY = 'sk-proj-abcdefghijklmnopqrstuvwxyz1234567890';
const OPENAI_LEGACY_KEY = 'sk-1234567890abcdefghijklmnopqrstuvwxyz1234567890';

// Anthropic key
const anthropicKey = 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890';

// GitHub tokens
const githubPAT = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz';
const githubOAuth = 'gho_1234567890abcdefghijklmnopqrstuvwxyz';
const githubFineGrained = 'github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz';

// Slack token
const slackToken = 'xoxb-1234567890123-1234567890123-abcdefghijklmnopqrstuvwx';

// Google API key
const googleApiKey = 'AIzaSyD1234567890abcdefghijklmnopqrstuvwxyz';

// Twilio
const twilioAccountSid = 'ACabcdef1234567890abcdef1234567890';
const twilioAuthToken = 'abcdef1234567890abcdef1234567890';

// Database connection string
const dbUrl = 'postgresql://admin:SuperSecret123@db.example.com:5432/production';

module.exports = {
  stripeConfig,
  OPENAI_API_KEY,
  anthropicKey,
  githubPAT,
  slackToken,
  googleApiKey,
  dbUrl
};
