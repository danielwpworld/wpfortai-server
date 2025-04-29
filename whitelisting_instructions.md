# Whitelisting Mechanism Instructions

## API Endpoints (All under `/api/scans/:domain/whitelist`)

### 1. Add File to Whitelist
```
POST /api/scans/:domain/whitelist
```
**Request Body:**
```
{
  "file_path": "/var/www/html/wp-content/plugins/plugin1/legit.php",
  "reason": "False positive - trusted file", // optional
  "added_by": "user" // optional
}
```
- `file_path` (string, required): Absolute path of the file to whitelist
- `reason` (string, optional): Reason for whitelisting
- `added_by` (string, optional): User or system identifier

**Example Response:**
```
{
  "status": "success",
  "whitelisted": {
    "id": 123,
    "website_id": "9ead9972-793a-42b0-890b-932820685742",
    "scan_detection_id": 456,
    "file_path": "/var/www/html/wp-content/plugins/plugin1/legit.php",
    "file_hash": "abc123...",
    "file_size": 2048,
    "detection_type": ["malware"],
    "reason": "False positive - trusted file",
    "whitelisted_at": "2025-04-29T09:37:00Z"
  }
}
```

---

### 2. Remove File from Whitelist
```
POST /api/scans/:domain/whitelist/remove
```
**Request Body:**
```
{
  "file_path": "/var/www/html/wp-content/plugins/plugin1/legit.php",
  "file_hash": "abc123..."
}
```
**Example Response:**
```
{
  "success": true
}
```

---

### 3. Fetch All Whitelisted Files
```
GET /api/scans/:domain/whitelist
```
**Example Response:**
```
{
  "whitelisted_files": [
    {
      "id": 123,
      "website_id": "9ead9972-793a-42b0-890b-932820685742",
      "scan_detection_id": 456,
      "file_path": "/var/www/html/wp-content/plugins/plugin1/legit.php",
      "file_hash": "abc123...",
      "file_size": 2048,
      "detection_type": ["malware"],
      "reason": "False positive - trusted file",
      "whitelisted_at": "2025-04-29T09:37:00Z"
    },
    // ... more files
  ]
}
```

---

### 4. Verify Whitelist Integrity
```
GET /api/scans/:domain/whitelist/verify
```
**Example Response:**
```
{
  "integrity": "ok",
  "details": [ /* ... */ ]
}
```

---

### 5. Cleanup Whitelist
```
POST /api/scans/:domain/whitelist/cleanup
```
**Example Response:**
```
{
  "success": true
}
```
}
```

## Notes
- Whitelisted files will be excluded from future detections and quarantine actions.

---

## Remove from Whitelist

### Endpoint
```
DELETE /:domain/whitelist
```

### Headers
- `Content-Type: application/json`
- `Authorization: Bearer <token>` (if authentication is enabled)

### Request Body
```json
{
  "file_path": "/var/www/html/wp-content/plugins/plugin1/legit.php"
}
```
- `file_path` (string, required): Absolute path of the file to remove from the whitelist

### Example Response
```json
{
  "status": "success",
  "removed": {
    "file_path": "/var/www/html/wp-content/plugins/plugin1/legit.php",
    "removed_at": "2025-04-29T09:39:00Z"
  }
}
```
