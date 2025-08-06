# Backup Webhooks Instructions

## Overview
These webhooks allow the WPSec plugin to send real-time backup progress updates and completion notifications to the WPFort backend server.

## Webhook Endpoints

### 1. Backup Progress
**Endpoint:** `POST /webhooks/backup-progress`

**Payload:**
```json
{
  "domain": "example.com",
  "backup_id": "backup_123456789",
  "status": "in_progress",
  "progress": 45.7
}
```

**Fields:**
- `domain` (required): Website domain
- `backup_id` (required): Unique backup identifier from WPSec
- `status` (optional): Current status - "pending", "in_progress"  
- `progress` (optional): Progress percentage (0-100), will be rounded to integer

---

### 2. Backup Complete
**Endpoint:** `POST /webhooks/backup-complete`

**Payload:**
```json
{
  "domain": "example.com",
  "backup_id": "backup_123456789"
}
```

**Fields:**
- `domain` (required): Website domain
- `backup_id` (required): Unique backup identifier from WPSec

**Note:** Automatically sets progress to 100% and syncs backup list from WPSec API.

---

### 3. Backup Failed  
**Endpoint:** `POST /webhooks/backup-failed`

**Payload:**
```json
{
  "domain": "example.com",
  "backup_id": "backup_123456789",
  "error_message": "Insufficient disk space"
}
```

**Fields:**
- `domain` (required): Website domain
- `backup_id` (required): Unique backup identifier from WPSec
- `error_message` (optional): Error description

## Headers
All webhook requests should include:
```
Content-Type: application/json
x-wpfort-token: <WPFORT_BACKEND_TOKEN>
```

## Response Format
All webhooks return:
```json
{
  "success": true
}
```

## Error Responses
```json
{
  "error": "Error description"
}
```

HTTP status codes:
- `400`: Missing required fields
- `404`: Website not found
- `500`: Internal server error

## Implementation Notes
- Domain is automatically converted to website_id internally
- Progress updates happen in real-time via database updates
- Backup completion triggers automatic sync of backup list from WPSec API
- All webhooks are non-blocking - database failures are logged but don't fail the webhook response