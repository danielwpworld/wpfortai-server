const crypto = require('crypto');

// The webhook secret
const webhookSecret = '1b3b79d0218e938d4777d65c70e0aa13a590e37151497f06cf87ade4d20be90c';

// Generate current timestamp
const timestamp = Math.floor(Date.now() / 1000).toString();

// Create a signature using the timestamp and webhook secret
const signature = crypto
  .createHmac('sha256', webhookSecret)
  .update(timestamp)
  .digest('hex');

console.log(`Timestamp: ${timestamp}`);
console.log(`Signature: ${signature}`);
console.log('\nUse these values in your webhook request headers:');
console.log(`X-WPFort-Timestamp: ${timestamp}`);
console.log(`X-WPFort-Signature: ${signature}`);
