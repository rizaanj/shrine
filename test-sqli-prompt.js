// Test script to verify the confirmation prompt works correctly

const readline = require('readline');

function askForConfirmation(question) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  return new Promise((resolve) => {
    rl.question(question + ' (y/N) ', (answer) => {
      rl.close();
      resolve(answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes');
    });
  });
}

async function test() {
  console.log('Testing confirmation prompt...');
  const confirmed = await askForConfirmation('Do you want to continue?');
  console.log(`User responded: ${confirmed}`);
  
  if (confirmed) {
    console.log('User confirmed! Would proceed with sqlmap...');
  } else {
    console.log('User declined. Aborting.');
  }
  
  process.exit(0);
}

test().catch(err => {
  console.error('Error:', err);
  process.exit(1);
});
