# Update Status Polling Guide

## Overview
This document explains how to poll the update status endpoint to track WordPress update operations.

## API Endpoint
```
GET /api/update/:domain/status
```

## Polling Implementation

### Basic Polling Function
```javascript
async function pollUpdateStatus(domain, interval = 5000, timeout = 300000) {
  const startTime = Date.now();
  
  while (Date.now() - startTime < timeout) {
    try {
      const response = await fetch(`/api/update/${domain}/status`);
      const data = await response.json();
      
      if (data.status === 'completed' || data.status === 'failed') {
        return data;
      }
      
      await new Promise(resolve => setTimeout(resolve, interval));
    } catch (error) {
      console.error('Error polling update status:', error);
    }
  }
  
  throw new Error('Update polling timed out');
}
```

### Response Format
```javascript
{
  status: string,        // 'pending', 'in-progress', 'completed', 'failed', or 'none'
  started_at: string,    // ISO timestamp when update started
  completed_at: string,  // ISO timestamp when update completed (if applicable)
  items: array,          // Items being updated (if applicable)
  domain: string,        // Website domain
  website_id: string     // UUID of the website
}
```

### Status Values
- `pending`: Update is queued but not started
- `in-progress`: Update is currently running
- `completed`: Update finished successfully
- `failed`: Update encountered an error
- `none`: No update found for this domain

## Best Practices
1. Use a reasonable polling interval (5-10 seconds)
2. Implement a timeout to prevent infinite polling
3. Handle network errors gracefully
4. Display update progress to users when possible
