// VULNERABLE: child_process exec with template string
const { exec, spawn, execSync, spawnSync } = require('child_process');

function vulnerableExec(userInput) {
  exec(`ls -la ${userInput}`);
  execSync(`cat ${userInput}`);
  spawn('sh', ['-c', `echo ${userInput}`]);
  spawnSync('cmd', ['/c', `type ${userInput}`]);
}

// SAFE: child_process exec with array args
const { execFile, spawn } = require('child_process');

function safeExec(userInput) {
  execFile('ls', ['-la', userInput]);
  spawn('cat', [userInput]);
}