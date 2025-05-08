# Core Reinstall Webhooks

This document describes the webhook endpoints for tracking WordPress core reinstall operations in WPFort Server. Use these endpoints to update the status of a core reinstall job.

---

## 1. Progress Webhook

**Endpoint:**
```
POST /api/webhooks/core-reinstall-progress
```

**Payload Example:**
```json
{
  "operation_id": "wpsec_core_reinstall_681cbc76de49b1.40995514",
  "status": "in_progress",
  "message": "Reinstall is running"
}
```

**Fields:**
- `operation_id` (string, required): The unique ID for the core reinstall operation (from WPSec API).
- `status` (string, required): The current status (e.g., `in_progress`).
- `message` (string, optional): Human-readable status message.

---

## 2. Complete Webhook

**Endpoint:**
```
POST /api/webhooks/core-reinstall-complete
```

**Payload Example:**
```json
{
  "operation_id": "wpsec_core_reinstall_681cbc76de49b1.40995514",
  "status": "completed",
  "message": "Reinstall completed successfully",
  "completed_at": "2025-05-08T14:17:30Z"
}
```

**Fields:**
- `operation_id` (string, required): The unique ID for the core reinstall operation.
- `status` (string, required): Should be `completed`.
- `message` (string, optional): Human-readable completion message.
- `completed_at` (string, optional): ISO8601 timestamp when the reinstall completed.

---

## 3. Failed Webhook

**Endpoint:**
```
POST /api/webhooks/core-reinstall-failed
```

**Payload Example:**
```json
{
  "operation_id": "wpsec_core_reinstall_681cbc76de49b1.40995514",
  "status": "failed",
  "error_message": "Checksum verification failed"
}
```

**Fields:**
- `operation_id` (string, required): The unique ID for the core reinstall operation.
- `status` (string, required): Should be `failed`.
- `error_message` (string, required): Error details or reason for failure.

---

## Notes
- All endpoints require `operation_id` as the primary identifier.
- Only send one webhook per event (progress, complete, or failed).
- Timestamps should be in ISO8601 format (e.g., `2025-05-08T14:17:30Z`).

---

For further details, see the implementation in `src/routes/webhooks.ts`.
