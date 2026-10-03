// config.js with hardcoded AWS credentials
const AWS = require('aws-sdk');

const awsConfig = {
  accessKeyId: 'AKIAI44QH8DHBEXAMPLE',
  secretAccessKey: 'je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY',
  region: 'us-east-1'
};

const s3 = new AWS.S3(awsConfig);

module.exports = { s3 };
