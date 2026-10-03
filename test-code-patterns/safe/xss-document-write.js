// SAFE: using DOM APIs instead of document.write
function safeDocumentWrite(userInput) {
  const h1 = document.createElement('h1');
  h1.textContent = userInput;
  document.body.appendChild(h1);
}