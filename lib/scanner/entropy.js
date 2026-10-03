/**
 * Calculate Shannon entropy for a given string
 * Formula: H(X) = -sum(p(x) * log2(p(x))) for each unique character
 * 
 * @param {string} str - The string to calculate entropy for
 * @returns {number} - The Shannon entropy value
 */
function calculateEntropy(str) {
  if (!str || str.length === 0) {
    return 0;
  }
  
  // Count frequency of each character
  const charCounts = {};
  for (const char of str) {
    charCounts[char] = (charCounts[char] || 0) + 1;
  }
  
  const length = str.length;
  let entropy = 0;
  
  // Calculate entropy using Shannon's formula
  for (const char in charCounts) {
    const probability = charCounts[char] / length;
    entropy -= probability * Math.log2(probability);
  }
  
  return entropy;
}

/**
 * Determine if a string is primarily base64 charset
 * @param {string} str - String to check
 * @returns {boolean}
 */
function isBase64Charset(str) {
  // Base64 uses: A-Z, a-z, 0-9, +, /, =
  const base64Only = /^[A-Za-z0-9+/=]+$/.test(str);
  if (!base64Only) return false;
  
  // Check if it has a mix of upper, lower, and digits (typical of base64)
  const hasUpper = /[A-Z]/.test(str);
  const hasLower = /[a-z]/.test(str);
  const hasDigit = /[0-9]/.test(str);
  
  // True base64 usually has at least 2 of these 3 types
  return [hasUpper, hasLower, hasDigit].filter(Boolean).length >= 2;
}

/**
 * Determine if a string is primarily hex charset
 * @param {string} str - String to check
 * @returns {boolean}
 */
function isHexCharset(str) {
  return /^[0-9a-fA-F]+$/.test(str);
}

module.exports = {
  calculateEntropy,
  isBase64Charset,
  isHexCharset
};
