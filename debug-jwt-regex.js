const testJwtNone = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.";
console.log('JWT:', testJwtNone);

// Test the current regex
const currentPattern = /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g;
console.log('Current pattern matches:', testJwtNone.match(currentPattern));

// Test a pattern that allows empty last segment
const allowEmptyPattern = /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]*/g;
console.log('Allow empty pattern matches:', testJwtNone.match(allowEmptyPattern));

// Test if we just need to make the last {10,} into {0,}
const lastFlexible = /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{0,}/g;
console.log('Last flexible pattern matches:', testJwtNone.match(lastFlexible));

// But we still need to ensure we match the whole token
const properPattern = /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]*/g;
console.log('Proper pattern matches:', testJwtNone.match(properPattern));

// Check what we actually have
const parts = testJwtNone.split('.');
console.log('Parts:', parts);
console.log('Number of parts:', parts.length);
console.log('Part 0 length:', parts[0].length);
console.log('Part 1 length:', parts[1].length);
console.log('Part 2 length:', parts[2].length);