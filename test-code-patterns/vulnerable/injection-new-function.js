// VULNERABLE: new Function with non-literal
function vulnerableNewFunction(userInput) {
  new Function(userInput)();
  new Function('a', 'b', 'return ' + userInput)(1, 2);
  new Function(`return ${userInput}`)();
}

// SAFE: new Function - only with literals
function safeNewFunction() {
  const fn = new Function('a', 'b', 'return a + b');
  return fn(1, 2);
}