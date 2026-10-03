#!/usr/bin/env node

/**
 * Generate top-1000 packages list from npm-high-impact
 * Combines high-impact, top-dependents, and top-downloads for comprehensive coverage
 */

import fs from 'fs';
import path from 'path';
import { npmHighImpact, npmTopDependents, npmTopDownloads } from 'npm-high-impact';

const OUTPUT_FILE = path.resolve('data/top-packages.json');
const TARGET_COUNT = 1000;

function generateTopPackages() {
  console.log('Generating top packages list...');
  
  const highImpact = new Set(npmHighImpact);
  const topDependents = new Set(npmTopDependents);
  const topDownloads = new Set(npmTopDownloads);
  
  console.log(`  npmHighImpact: ${highImpact.size} packages`);
  console.log(`  npmTopDependents: ${topDependents.size} packages`);
  console.log(`  npmTopDownloads: ${topDownloads.size} packages`);
  
  // Priority order: high impact first, then top dependents, then top downloads
  const combined = [
    ...npmHighImpact,
    ...npmTopDependents.filter(p => !highImpact.has(p)),
    ...npmTopDownloads.filter(p => !highImpact.has(p) && !topDependents.has(p))
  ];
  
  // Take first 1000
  const top1000 = combined.slice(0, TARGET_COUNT);
  
  console.log(`  Combined unique: ${new Set(combined).size} packages`);
  console.log(`  Selected top ${top1000.length} packages`);
  
  // Save to file
  fs.writeFileSync(OUTPUT_FILE, JSON.stringify(top1000, null, 2));
  console.log(`\nSaved to ${OUTPUT_FILE}`);
  
  // Show 10 random names
  const shuffled = [...top1000].sort(() => Math.random() - 0.5);
  console.log('\n10 random names:');
  console.log(shuffled.slice(0, 10).join(', '));
  
  return top1000;
}

generateTopPackages();