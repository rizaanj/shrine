// SAFE: child_process exec with array args
const { execFile, spawn } = require('child_process');

function safeExec(userInput) {
  execFile('ls', ['-la', userInput]);
  spawn('cat', [userInput]);
}