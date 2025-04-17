const crypto = require('crypto');
const https = require('https');
const http = require('http');

// Configuration
const webhookSecret = 'aafa0d6d4f133b79795720f3ab9ca30d9a7e793ce3ba2d07c6fd1bc63f7ce080';
const scanId = 'wpsec_680085f19a2d26.84555205';
const payload = JSON.stringify({ scan_id: scanId });
const timestamp = Math.floor(Date.now() / 1000).toString();

// Generate signature
const signatureData = `${timestamp}.${payload}`;
const signature = crypto
  .createHmac('sha256', webhookSecret)
  .update(signatureData)
  .digest('hex');

// Create request options
const options = {
  hostname: 'localhost',
  port: 3001,
  path: '/api/webhooks/scan-complete',
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'x-wpfort-signature': signature,
    'x-wpfort-timestamp': timestamp,
    'Content-Length': Buffer.byteLength(payload)
  }
};

// Send request
const req = http.request(options, (res) => {
  console.log(`STATUS: ${res.statusCode}`);
  console.log(`HEADERS: ${JSON.stringify(res.headers)}`);
  
  let data = '';
  res.on('data', (chunk) => {
    data += chunk;
  });
  
  res.on('end', () => {
    console.log('Response body:', data);
  });
});

req.on('error', (e) => {
  console.error(`Problem with request: ${e.message}`);
});

// Write data to request body
req.write(payload);
req.end();

console.log('Webhook request sent with:');
console.log(`- Scan ID: ${scanId}`);
console.log(`- Timestamp: ${timestamp}`);
console.log(`- Signature: ${signature}`);
