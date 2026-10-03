// SAFE: innerHTML assignment
function safeInnerHTML(userInput) {
  document.getElementById('output').textContent = userInput;
  const div = document.createElement('div');
  div.textContent = userInput;
  element.appendChild(div);
}