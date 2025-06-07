# Assessment Worker - Redis Key Guide

## Key Structure

### 1. Assessment Entry
**Key Pattern**: `assessment:{assessmentId}`  
**TTL**: 7 days

**Initial State (Pending):**
```json
{
  "assessment_id": "assess_abc123",
  "website_id": "7491dbe0-b133-4f29-9ee7-3f1f055f7c49",
  "domain": "example.com",
  "status": "pending",
  "started_at": "2025-05-31T10:00:00.000Z"
}
```

**Processing State:**
```json
{
  "assessment_id": "assess_abc123",
  "website_id": "7491dbe0-b133-4f29-9ee7-3f1f055f7c49",
  "domain": "example.com",
  "status": "processing",
  "started_at": "2025-05-31T10:00:00.000Z",
  "progress": 25,
  "current_step": "Scanning core files"
}
```

**Completed State:**
```json
{
  "assessment_id": "assess_abc123",
  "website_id": "7491dbe0-b133-4f29-9ee7-3f1f055f7c49",
  "domain": "example.com",
  "status": "completed",
  "started_at": "2025-05-31T10:00:00.000Z",
  "completed_at": "2025-05-31T10:02:30.000Z",
  "results": {
    "action_items": [
      {
        "action": "Update WordPress Core",
        "risk_score": 8,
        "data": { /* ... */ }
      }
    ]
  }
}
```

### 2. Active Assessment Reference
**Key Pattern**: `active_assessment:{domain}`  
**TTL**: Same as assessment entry

**Value**: `assessmentId` (e.g., `"assess_abc123"`)

## Worker Flow

1. **Find Pending Jobs**
   ```javascript
   // Find all pending assessments
   const pendingKeys = await redis.keys('assessment:*:pending');
   ```

2. **Update to Processing**
   ```javascript
   await redis.set(
     `assessment:${assessmentId}`, 
     JSON.stringify({
       ...assessment,
       status: 'processing',
       progress: 0,
       current_step: 'Starting assessment'
     }),
     'KEEPTTL' // Maintain original TTL
   );
   ```

3. **Update Progress**
   ```javascript
   // During processing, update progress
   await redis.set(
     `assessment:${assessmentId}`,
     JSON.stringify({
       ...assessment,
       progress: 50,
       current_step: 'Analyzing vulnerabilities'
     }),
     'KEEPTTL'
   );
   ```

4. **Mark Complete**
   ```javascript
   await redis.set(
     `assessment:${assessmentId}`,
     JSON.stringify({
       ...assessment,
       status: 'completed',
       progress: 100,
       completed_at: new Date().toISOString(),
       results: { /* ... */ }
    }),
    'EX', 60 * 60 * 24 * 7 // 7 days TTL
   );
   
   // Clear active assessment reference
   await redis.del(`active_assessment:${domain}`);
   ```

## Error Handling

For failed assessments:
```javascript
await redis.set(
  `assessment:${assessmentId}`,
  JSON.stringify({
    ...assessment,
    status: 'failed',
    error: 'Failed to process: ' + error.message,
    completed_at: new Date().toISOString()
  }),
  'EX', 60 * 60 * 24 * 7
);
```