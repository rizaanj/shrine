// VULNERABLE: dangerouslySetInnerHTML
function VulnerableComponent({ userInput }) {
  return <div dangerouslySetInnerHTML={{ __html: userInput }} />;
}

// SAFE: dangerouslySetInnerHTML
import DOMPurify from 'dompurify';

function SafeComponent({ userInput }) {
  const clean = DOMPurify.sanitize(userInput);
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}