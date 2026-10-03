// Day 4 AST Test Fixtures

// Test 1: Secret in comment - should NOT be detected by AST (but would be by regex)
// const apiKey = "AKIAI44QH8DHBEXAMPLE";
// const secret = "sk_live_51HqF8xHH1234567890abcdefghijklmno";

// Test 2: Real assignment - SHOULD be detected with HIGH confidence
const apiKey = "sk_live_51HqF8xHH9876543210zyxwvutsrqponml";

// Test 3: Object property - SHOULD be detected
const config = {
  secretKey: "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
  endpoint: "https://api.example.com"
};

// Test 4: Function call - SHOULD be detected
function initialize() {
  setApiKey("sk-proj-NewAPIKey1234567890abcdefghij");
}

// Test 5: Template placeholder - should NOT be detected
const envKey = "${API_KEY}";
const emptyKey = "";

// Test 6: Non-secret variable - should NOT be detected (no secret keyword)
const randomVariable = "sk_live_12345678901234567890123456789012";

// Test 7: Secret in multiline comment block - should NOT be detected
/*
const twilioKey = "AC1234567890abcdef1234567890abcdef";
const stripeKey = "sk_live_abc123def456ghi789jkl012mno345";
*/

// Test 8: Real GitHub token in authorization
const headers = {
  Authorization: "ghp_abcdef1234567890GHIJKLMNOPQRSTUVWXYZ"
};

module.exports = {
  apiKey,
  config,
  initialize
};
