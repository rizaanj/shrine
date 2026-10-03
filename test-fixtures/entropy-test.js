// Entropy test fixtures - Day 3

// Should be detected: high-entropy base64 string with context
const api_key = "Kj8vN2mP9xQ4sL7wR6tY3zA5bC1dE0fG";

// Should be detected: random base64 with token keyword
const secret_token = "8sK3mL9pN2vX5zR7wQ4tY6bA1cD0eF3g";

// Should NOT be detected: high entropy but no context keyword
const randomValue = "X8kP3mL9vN2xQ5zR7wY4tA6bC1dE0fG3";

// Should NOT be detected: low entropy (all same character)
const lowEntropy = "aaaaaaaaaaaaaaaaaaaa";

// Should be detected: hex string with credential keyword
const db_credential = "a1b2c3d4e5f67890abcdef1234567890";

module.exports = {
  api_key,
  secret_token,
  randomValue,
  lowEntropy,
  db_credential
};
