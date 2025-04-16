# WPFort Webhook System

## Quick Start

1. **Generate a Webhook Secret**
```bash
curl -X POST http://localhost:3001/api/webhook-secrets/example.com/webhook-secret
```

This will return:
```json
{
  "secret": "your-secret-key-here",
  "instructions": {
    "headers": {
      "x-wpfort-signature": "HMAC SHA256 signature",
      "x-wpfort-timestamp": "Unix timestamp"
    }
  }
}
```

2. **Store the Secret in WordPress**
```php
// In your plugin's settings
update_option('wpfort_webhook_secret', $response['secret']);
```

3. **Call a Webhook (Complete Example)**
```php
// 1. Get your stored secret
$secret = get_option('wpfort_webhook_secret');

// 2. Prepare your payload
$payload = [
    'scan_id' => 'scan-123',
    'status' => 'running',
    'progress' => 45
];

// 3. Generate signature
$timestamp = time();
$payload_json = json_encode($payload);
$signature_data = $timestamp . '.' . $payload_json;
$signature = hash_hmac('sha256', $signature_data, $secret);

// 4. Make the webhook call
$response = wp_remote_post('http://localhost:3001/api/webhooks/scan-progress', [
    'headers' => [
        'Content-Type' => 'application/json',
        'x-wpfort-signature' => $signature,
        'x-wpfort-timestamp' => $timestamp
    ],
    'body' => $payload_json
]);

// 5. Handle response
if (is_wp_error($response)) {
    error_log('Webhook failed: ' . $response->get_error_message());
} else {
    $status_code = wp_remote_retrieve_response_code($response);
    if ($status_code !== 200) {
        error_log('Webhook failed with status: ' . $status_code);
    }
}
```

4. **Test Your Integration**
Use our Postman collection to test your webhook implementation:
```bash
# 1. Import the collection
postman import WPFort-Webhooks.postman_collection.json

# 2. Set your environment variables
base_url=http://localhost:3001/api
domain=your-site.com
webhook_secret=your-secret-from-step-1
```

## Overview
The WPFort webhook system allows WordPress plugins to securely communicate scan progress and results back to the WPFort server. All webhooks are protected using HMAC signatures to ensure authenticity and prevent tampering.

## Security Model

### Secret Rotation
Webhook secrets are managed with a secure rotation system:

1. **Automatic Rotation**
   - Secrets are automatically rotated after 90 days of use
   - During rotation, both old and new secrets work for 24 hours
   - After 24 hours, only the new secret is valid

2. **Manual Rotation**
   - You can manually rotate secrets using the API
   - Same 24-hour grace period applies
   - Use this for security incidents or compliance

3. **Best Practices**
   - Store the secret securely in WordPress
   - Update your secret when rotation occurs
   - Monitor for 401 errors (indicates invalid secret)
   - Keep your plugin's error logging enabled
- Each website has its own unique webhook secret
- Every request must be signed using HMAC-SHA256
- Timestamps prevent replay attacks
- 5-minute time window for request validity
- Automatic secret rotation support

## Getting Started

### 1. Generate a Webhook Secret
```bash
curl -X POST http://localhost:3001/api/webhook-secrets/example.com/webhook-secret
```

Response:
```json
{
  "secret": "your-secret-key",
  "instructions": {
    "headers": {
      "x-wpfort-signature": "HMAC SHA256 signature of timestamp.payload",
      "x-wpfort-timestamp": "Current Unix timestamp in seconds"
    }
  }
}
```

### 2. Implement Webhook Signing (PHP)
```php
function sign_wpfort_webhook($payload, $secret) {
    $timestamp = time();
    $payload_json = json_encode($payload);
    $signature_data = $timestamp . '.' . $payload_json;
    $signature = hash_hmac('sha256', $signature_data, $secret);

    return [
        'signature' => $signature,
        'timestamp' => $timestamp
    ];
}

function send_wpfort_webhook($endpoint, $payload, $secret) {
    $signature_data = sign_wpfort_webhook($payload, $secret);
    
    return wp_remote_post('http://localhost:3001/api/webhooks/' . $endpoint, [
        'headers' => [
            'Content-Type' => 'application/json',
            'x-wpfort-signature' => $signature_data['signature'],
            'x-wpfort-timestamp' => $signature_data['timestamp']
        ],
        'body' => json_encode($payload)
    ]);
}
```

## Available Webhooks

### Scan Progress Update
Updates the progress of an ongoing scan.

```php
send_wpfort_webhook('scan-progress', [
    'scan_id' => 'scan-123',
    'status' => 'running',
    'progress' => 45,
    'files_scanned' => '450',
    'total_files' => '1000'
], $secret);
```

### Scan Failed
Marks a scan as failed with an error message.

```php
send_wpfort_webhook('scan-failed', [
    'scan_id' => 'scan-123',
    'error_message' => 'Failed to access file: wp-content/uploads/malware.php'
], $secret);
```

### Scan Complete
Marks a scan as completed and triggers result processing.

```php
send_wpfort_webhook('scan-complete', [
    'scan_id' => 'scan-123'
], $secret);
```

## Security Best Practices

1. **Store Secrets Securely**
   - Use WordPress options API with encryption
   - Never expose secrets in public areas
   ```php
   update_option('wpfort_webhook_secret', wp_encrypt($secret));
   ```

2. **Handle Failed Requests**
   - Implement exponential backoff for retries
   - Log failed webhook attempts
   ```php
   if (is_wp_error($response)) {
       wpfort_log_webhook_error($response->get_error_message());
       schedule_retry_with_backoff();
   }
   ```

3. **Rotate Secrets Regularly**
   - Implement automatic secret rotation
   - Keep old secret valid for a short period
   ```php
   // Every 30 days
   if (time() - get_option('wpfort_secret_created_at') > 30 * 24 * 60 * 60) {
       rotate_wpfort_webhook_secret();
   }
   ```

## Testing Webhooks
A Postman collection is available at `/postman/WPFort-Webhooks.postman_collection.json` with pre-configured requests and automatic signature generation.
