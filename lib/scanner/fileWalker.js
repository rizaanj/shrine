const fg = require('fast-glob');
const fs = require('fs').promises;
const path = require('path');

// Full coverage by default: skip only binaries, node_modules, and .git.
// No size caps, no minified-file skips. Large files stream via secretDetector.
// Pass respectGitignore=true (CLI --respect-gitignore) to opt into .gitignore filtering.
const DEFAULT_IGNORE_PATTERNS = [
  '**/node_modules/**',
  '.git/**'
];

const BINARY_EXTENSIONS = [
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.pdf', '.zip', '.tar', '.gz',
  '.exe', '.dll', '.so', '.dylib', '.bin', '.dat', '.db', '.sqlite',
  '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.avi', '.mov'
];

const STREAMING_THRESHOLD = 10 * 1024 * 1024; // 10MB - files larger than this use streaming

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

async function scanDirectory(targetPath, verbose = false, respectGitignore = false) {
  const skippedFiles = [];

  // .gitignore is opt-in only (--respect-gitignore); default scans everything
  const gitignorePatterns = respectGitignore ? await parseGitignore(targetPath) : [];

  // Combine default ignore patterns with .gitignore patterns (if opted in)
  const allIgnorePatterns = respectGitignore
    ? [...DEFAULT_IGNORE_PATTERNS, ...gitignorePatterns]
    : DEFAULT_IGNORE_PATTERNS;

  if (verbose && respectGitignore && gitignorePatterns.length > 0) {
    console.log(`Loaded ${gitignorePatterns.length} patterns from .gitignore`);
  }

  if (verbose && respectGitignore) {
    console.log('Respecting .gitignore patterns');
  }

  // Find all files
  const files = await fg('**/*', {
    cwd: targetPath,
    ignore: allIgnorePatterns,
    onlyFiles: true,
    dot: true, // Include dotfiles
    absolute: true
  });

  // Skip binaries only, recording the reason for each skipped file
  const textFiles = [];
  for (const file of files) {
    if (isBinaryFile(file)) {
      if (verbose) {
        console.log(`Skipping binary file: ${file}`);
      }
      skippedFiles.push({ path: file, reason: 'binary file extension' });
      continue;
    }

    textFiles.push(file);
  }

  return { files: textFiles, skipped: skippedFiles };
}

module.exports = { scanDirectory, STREAMING_THRESHOLD };
