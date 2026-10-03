// SAFE: new Function - only with literals
function safeNewFunction() {
  const fn = new Function('a', 'b', 'return a + b');
  return fn(1, 2);
}