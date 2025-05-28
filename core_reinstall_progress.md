

## Checking Core Reinstall Status

You can check the status of an active core reinstall for a domain by using the Redis store directly. There are two ways to retrieve this information:

### Option 1: Check Active Reinstall by Domain

To check if there's an active core reinstall for a domain and get its status:

```javascript
// Example code for retrieving from Redis
const { CoreReinstallStore } = require('../services/core-reinstall-store');
const reinstallData = await CoreReinstallStore.getActiveCoreReinstall(domain);

if (reinstallData) {
  console.log('Active reinstall:', reinstallData);
} else {
  console.log('No active reinstall for this domain');
}
```

### Option 2: Check Reinstall by Operation ID

If you have the operation_id from a previous reinstall operation:

```javascript
// Example code for retrieving from Redis
const { CoreReinstallStore } = require('../services/core-reinstall-store');
const reinstallData = await CoreReinstallStore.getCoreReinstall(operationId);

if (reinstallData) {
  console.log('Reinstall status:', reinstallData);
} else {
  console.log('No reinstall found with this operation ID');
}
```


## Status Values

The core reinstall process can have the following status values:

- `pending`: The reinstall has been initiated but not yet started
- `in_progress`: The reinstall is currently in progress
- `completed`: The reinstall has completed successfully
- `failed`: The reinstall has failed

## Data Structure

The core reinstall data structure contains:

```json
{
  "domain": "example.com",
  "operation_id": "operation_12345",
  "started_at": "2025-05-28T07:14:42.000Z",
  "status": "in_progress",
  "message": "Downloading WordPress files...",
  "version": "current",
  "completed_at": null,
  "error_message": null,
  "check_status_endpoint": "/status"
}
```
