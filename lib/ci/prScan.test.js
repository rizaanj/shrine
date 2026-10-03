const childProcess = require('child_process');

// Store original spawnSync
const originalSpawnSync = childProcess.spawnSync;

// Test (a): Mock gh CLI success + shrine scan exitCode=1 + high findings
console.log('Test (a): gh CLI success + scan exitCode=1 + high findings');
let spawnCallCount = 0;
childProcess.spawnSync = function(cmd, args, opts) {
  spawnCallCount++;
  
  // gh --version
  if (cmd === 'gh' && args[0] === '--version') {
    return { status: 0, stdout: 'gh version 2.0.0', stderr: '' };
  }
  
  // git remote get-url origin
  if (cmd === 'git' && args[0] === 'remote') {
    return { status: 0, stdout: 'https://github.com/user/repo.git\n', stderr: '' };
  }
  
  // gh pr checkout
  if (cmd === 'gh' && args[0] === 'pr' && args[1] === 'checkout') {
    return { status: 0, stdout: 'Checked out PR #123', stderr: '' };
  }
  
  // node shrine.js scan
  if (cmd === 'node' && args[1] === 'scan') {
    return { status: 1, stdout: 'Total findings: 3\nHigh severity: 2\n', stderr: '', error: null };
  }
  
  // gh pr comment
  if (cmd === 'gh' && args[0] === 'pr' && args[1] === 'comment') {
    const body = args[4];
    console.assert(body.includes('BLOCK'), 'Comment should contain BLOCK');
    return { status: 0, stdout: 'Comment posted', stderr: '' };
  }
  
  return originalSpawnSync(cmd, args, opts);
};

const { scanPR } = require('./prScan');

scanPR({ prNumber: 123, provider: 'github', targetPath: '/test', verbose: false })
  .then(result => {
    if (result.blockMerge !== true) throw new Error('Should block merge');
    if (result.findings.total !== 3) throw new Error('Should have 3 total findings');
    if (result.findings.high !== 2) throw new Error('Should have 2 high findings');
    console.log('PASS: blockMerge=true, comment contains BLOCK');
    
    // Test (b): Mock gh CLI success + shrine scan exitCode=0 + no findings
    console.log('\nTest (b): gh CLI success + scan exitCode=0 + no findings');
    spawnCallCount = 0;
    childProcess.spawnSync = function(cmd, args, opts) {
      spawnCallCount++;
      
      if (cmd === 'gh' && args[0] === '--version') {
        return { status: 0, stdout: 'gh version 2.0.0', stderr: '' };
      }
      
      if (cmd === 'git' && args[0] === 'remote') {
        return { status: 0, stdout: 'https://github.com/user/repo.git\n', stderr: '' };
      }
      
      if (cmd === 'gh' && args[0] === 'pr' && args[1] === 'checkout') {
        return { status: 0, stdout: 'Checked out PR #456', stderr: '' };
      }
      
      if (cmd === 'node' && args[1] === 'scan') {
        return { status: 0, stdout: 'Total findings: 0\nHigh severity: 0\n', stderr: '', error: null };
      }
      
      if (cmd === 'gh' && args[0] === 'pr' && args[1] === 'comment') {
        const body = args[4];
        if (!body.includes('Safe to merge')) {
          throw new Error('Comment should contain Safe to merge, got: ' + body);
        }
        return { status: 0, stdout: 'Comment posted', stderr: '' };
      }
      
      return originalSpawnSync(cmd, args, opts);
    };
    
    return scanPR({ prNumber: 456, provider: 'github', targetPath: '/test', verbose: false });
  })
  .then(result => {
    if (result.blockMerge !== false) {
      throw new Error(`Should not block merge. Got blockMerge=${result.blockMerge}, findings.high=${result.findings.high}, findings.total=${result.findings.total}`);
    }
    if (result.findings.total !== 0) throw new Error('Should have 0 findings');
    console.log('PASS: blockMerge=false, comment contains Safe to merge');
    
    // Test (c): Mock gh --version throw
    console.log('\nTest (c): gh --version throw => No gh/glab CLI found');
    childProcess.spawnSync = function(cmd, args, opts) {
      if (cmd === 'gh' && args[0] === '--version') {
        return { status: 1, stdout: '', stderr: 'command not found' };
      }
      
      if (cmd === 'glab' && args[0] === '--version') {
        return { status: 1, stdout: '', stderr: 'command not found' };
      }
      
      return originalSpawnSync(cmd, args, opts);
    };
    
    return scanPR({ prNumber: 789, targetPath: '/test', verbose: false })
      .then(() => {
        throw new Error('Should have thrown');
      })
      .catch(error => {
        if (error.message === 'No gh/glab CLI found') {
          console.log('PASS: error=' + error.message);
        } else {
          throw error;
        }
      });
  })
  .then(() => {
    // Test (d): Mock gh pr checkout throw
    console.log('\nTest (d): gh pr checkout throw => PR checkout failed');
    childProcess.spawnSync = function(cmd, args, opts) {
      if (cmd === 'gh' && args[0] === '--version') {
        return { status: 0, stdout: 'gh version 2.0.0', stderr: '' };
      }
      
      if (cmd === 'git' && args[0] === 'remote') {
        return { status: 0, stdout: 'https://github.com/user/repo.git\n', stderr: '' };
      }
      
      if (cmd === 'gh' && args[0] === 'pr' && args[1] === 'checkout') {
        return { status: 1, stdout: '', stderr: 'PR not found' };
      }
      
      return originalSpawnSync(cmd, args, opts);
    };
    
    return scanPR({ prNumber: 999, provider: 'github', targetPath: '/test', verbose: false })
      .then(() => {
        throw new Error('Should have thrown');
      })
      .catch(error => {
        if (error.message.includes('PR checkout failed')) {
          console.log('PASS: error=' + error.message);
        } else {
          throw error;
        }
      });
  })
  .then(() => {
    // Test (e): Mock gh pr comment throw => console.warn, no crash
    console.log('\nTest (e): gh pr comment throw => console.warn, no crash, still blockMerge=true');
    let warnCalled = false;
    const originalWarn = console.warn;
    console.warn = function(...args) {
      if (args[0].includes('Comment failed')) {
        warnCalled = true;
      }
    };
    
    childProcess.spawnSync = function(cmd, args, opts) {
      if (cmd === 'gh' && args[0] === '--version') {
        return { status: 0, stdout: 'gh version 2.0.0', stderr: '' };
      }
      
      if (cmd === 'git' && args[0] === 'remote') {
        return { status: 0, stdout: 'https://github.com/user/repo.git\n', stderr: '' };
      }
      
      if (cmd === 'gh' && args[0] === 'pr' && args[1] === 'checkout') {
        return { status: 0, stdout: 'Checked out PR #111', stderr: '' };
      }
      
      if (cmd === 'node' && args[1] === 'scan') {
        return { status: 1, stdout: 'Total findings: 5\nHigh severity: 3\n', stderr: '', error: null };
      }
      
      if (cmd === 'gh' && args[0] === 'pr' && args[1] === 'comment') {
        return { status: 1, stdout: '', stderr: 'API rate limit exceeded' };
      }
      
      return originalSpawnSync(cmd, args, opts);
    };
    
    return scanPR({ prNumber: 111, provider: 'github', targetPath: '/test', verbose: false })
      .then(result => {
        if (warnCalled !== true) throw new Error('Should call console.warn');
        if (result.blockMerge !== true) throw new Error('Should still block merge');
        if (result.findings.total !== 5) throw new Error('Should have 5 findings');
        if (result.findings.high !== 3) throw new Error('Should have 3 high findings');
        console.log('PASS: console.warn called, no crash, blockMerge=true');
        
        // Restore
        console.warn = originalWarn;
        childProcess.spawnSync = originalSpawnSync;
        
        console.log('\nAll tests passed!');
      });
  })
  .catch(error => {
    console.error('Test failed:', error);
    process.exit(1);
  });
