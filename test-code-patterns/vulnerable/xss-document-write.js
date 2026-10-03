// VULNERABLE: document.write
function vulnerableDocumentWrite(userInput) {
  document.write('<h1>' + userInput + '</h1>');
  document.write(`<script>alert('${userInput}')</script>`);
}

// SAFE: document.write - not really safe, but using DOM APIs
function safeDocumentWrite(userInput) {
  const h1 = document.createElement('h1');
  h1.textContent = userInput;
  document.body.appendChild(h1);
}