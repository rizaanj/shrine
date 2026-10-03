// SAFE: eval - only with literal (or avoid entirely)
function safeEval() {
  // Only safe if literal
  eval('console.log("static code")');
  // Better: avoid eval entirely
  Function('"use strict"; console.log("static")')();
}