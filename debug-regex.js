const testJwtNone = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.";

console.log('Test JWT:', testJwtNone);
console.log('Length:', testJwtNone.length);

// Test the JWT regex directly
const jwtPattern = /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g;
console.log('JWT pattern:', jwtPattern);

const matches = testJwtNone.match(jwtPattern);
console.log('Matches:', matches);

if (matches) {
  console.log('First match:', matches[0]);
  console.log('Match length:', matches[0].length);
  console.log('Equal?', matches[0] === testJwtNone);
}

// Test with extra spaces
const withSpaces = `  ${testJwtNone}  `;
console.log('\nWith spaces:', JSON.stringify(withSpaces));
const matchesWithSpaces = withSpaces.match(jwtPattern);
console.log('Matches with spaces:', matchesWithSpaces);