const fg = require('fast-glob');
const fs = require('fs').promises;
const path = require('path');

const DEFAULT_IGNORE_PATTERNS = [
  '**/node_modules/**',
  '.git/**',
  'dist/**',
  'build/**',
  '*.min.js',
  '*.bundle.js',
  '*.map',
  '**/your-*-key/**',
  '**/your-*-key',
  '**/your-*-key.*'
];

const BINARY_EXTENSIONS = [
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.pdf', '.zip', '.tar', '.gz',
  '.exe', '.dll', '.so', '.dylib', '.bin', '.dat', '.db', '.sqlite',
  '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.avi', '.mov'
];

const MAX_FILE_SIZE = 2 * 1024 * 1024; // 2MB

async function parseGitignore(targetPath) {
  const gitignorePath = path.join(targetPath, '.gitignore');
  const patterns = [];
  
  try {
    const content = await fs.readFile(gitignorePath, 'utf-8');
    const lines = content.split('\n');
    
    for (const line of lines) {
      const trimmed = line.trim();
      // Skip empty lines and comments
      if (trimmed && !trimmed.startsWith('#')) {
        // Convert .gitignore patterns to fast-glob patterns
        let pattern = trimmed;
        if (!pattern.includes('/') && !pattern.includes('*')) {
          // If it's just a name, match it anywhere
          pattern = `**/${pattern}/**`;
        } else if (!pattern.endsWith('/') && !pattern.includes('*')) {
          // Add /** to match directories recursively
          pattern = `${pattern}/**`;
        }
        patterns.push(pattern);
      }
    }
  } catch (error) {
    // .gitignore doesn't exist or can't be read, that's fine
  }
  
  return patterns;
}

function isBinaryFile(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  return BINARY_EXTENSIONS.includes(ext);
}

async function isFileTooLarge(filePath) {
  try {
    const stats = await fs.stat(filePath);
    return stats.size > MAX_FILE_SIZE;
  } catch (error) {
    return true; // Skip files we can't stat
  }
}

async function scanDirectory(targetPath, verbose = false) {
  // Parse .gitignore patterns
  const gitignorePatterns = await parseGitignore(targetPath);
  
  // Combine default ignore patterns with .gitignore patterns
  const allIgnorePatterns = [...DEFAULT_IGNORE_PATTERNS, ...gitignorePatterns];
  
  if (verbose && gitignorePatterns.length > 0) {
    console.log(`Loaded ${gitignorePatterns.length} patterns from .gitignore`);
  }
  
  // Find all files
  const files = await fg('**/*', {
    cwd: targetPath,
    ignore: allIgnorePatterns,
    onlyFiles: true,
    dot: true, // Include dotfiles
    absolute: true
  });
  
  // Filter out binary files and files that are too large
  const textFiles = [];
  for (const file of files) {
    if (isBinaryFile(file)) {
      if (verbose) {
        console.log(`Skipping binary file: ${file}`);
      }
      continue;
    }
    
    if (await isFileTooLarge(file)) {
      if (verbose) {
        console.log(`Skipping large file: ${file}`);
      }
      continue;
    }
    
    textFiles.push(file);
  }
  
  return textFiles;
}

module.exports = { scanDirectory };
