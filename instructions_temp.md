# WPFort Scanning Guide

This guide explains how to initiate a website security scan and track its progress using the WPFort API.

## Starting a Scan

To start a new security scan for a website:

```javascript
// Example using fetch API
async function startScan(domain) {
  try {
    const response = await fetch(`http://localhost:3001/api/scans/${domain}/start`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      }
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.error || 'Failed to start scan');
    }
    
    return data; // Contains scan_id and started_at timestamp
  } catch (error) {
    console.error('Error starting scan:', error);
    throw error;
  }
}
```

The response will include:
- `scan_id`: Unique identifier for the scan
- `started_at`: Timestamp when the scan was initiated

## Tracking Scan Progress

Once a scan is initiated, you can track its progress by polling the status endpoint:

```javascript
async function getScanStatus(domain, scanId) {
  try {
    const response = await fetch(`http://localhost:3001/api/scans/${domain}/status/${scanId}`);
    
    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.error || 'Failed to get scan status');
    }
    
    return data;
  } catch (error) {
    console.error('Error getting scan status:', error);
    throw error;
  }
}
```

The status response includes:
- `status`: Current scan status ('pending', 'running', 'completed', or 'failed')
- `progress`: Percentage of completion (0-100)
- `files_scanned`: Number of files scanned so far
- `total_files`: Total number of files to scan
- `completed_at`: Timestamp when the scan completed (if status is 'completed')
- `duration`: Duration of the scan in seconds (if completed)
- `error`: Error message (if status is 'failed')

## Checking for Active Scans

Before starting a new scan, you may want to check if there's already an active scan for the domain:

```javascript
async function getActiveScan(domain) {
  try {
    const response = await fetch(`http://localhost:3001/api/scans/${domain}/active`);
    
    // If status is 404, there's no active scan
    if (response.status === 404) {
      return null;
    }
    
    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.error || 'Failed to get active scan');
    }
    
    return data; // Contains active scan details
  } catch (error) {
    console.error('Error checking for active scan:', error);
    throw error;
  }
}
```

## Getting Scan Results

Once a scan is completed, you can retrieve the detailed results:

```javascript
async function getScanResults(domain, scanId) {
  try {
    const response = await fetch(`http://localhost:3001/api/scans/${domain}/results/${scanId}`);
    
    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.error || 'Failed to get scan results');
    }
    
    return data;
  } catch (error) {
    console.error('Error getting scan results:', error);
    throw error;
  }
}
```

The results include:
- `infected_files`: Array of detected malicious files
- `total_files_count`: Total number of files scanned
- `infected_files_count`: Number of infected files found
- `scan_duration`: Duration of the scan in seconds

## Implementing a Progress UI

Here's an example of how to implement a progress tracking UI using React:

```jsx
import React, { useState, useEffect } from 'react';

function ScanProgress({ domain, scanId }) {
  const [scanStatus, setScanStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let intervalId;
    
    const checkStatus = async () => {
      try {
        setLoading(true);
        const status = await getScanStatus(domain, scanId);
        setScanStatus(status);
        
        // If scan is completed or failed, stop polling
        if (status.status === 'completed' || status.status === 'failed') {
          clearInterval(intervalId);
        }
      } catch (err) {
        setError(err.message);
        clearInterval(intervalId);
      } finally {
        setLoading(false);
      }
    };
    
    // Check immediately and then every 5 seconds
    checkStatus();
    intervalId = setInterval(checkStatus, 5000);
    
    return () => clearInterval(intervalId);
  }, [domain, scanId]);
  
  if (loading && !scanStatus) {
    return <div>Loading scan status...</div>;
  }
  
  if (error) {
    return <div>Error: {error}</div>;
  }
  
  if (!scanStatus) {
    return <div>No scan data available</div>;
  }
  
  return (
    <div className="scan-progress">
      <h2>Scan Progress</h2>
      <div className="status">Status: {scanStatus.status}</div>
      
      {scanStatus.status === 'running' && (
        <>
          <div className="progress-bar">
            <div 
              className="progress-fill" 
              style={{ width: `${scanStatus.progress || 0}%` }}
            ></div>
          </div>
          <div className="progress-text">
            {scanStatus.progress || 0}% complete
          </div>
          <div className="files-scanned">
            Files scanned: {scanStatus.files_scanned || 0} / {scanStatus.total_files || '?'}
          </div>
        </>
      )}
      
      {scanStatus.status === 'completed' && (
        <div className="completion-info">
          <div>Scan completed at: {new Date(scanStatus.completed_at).toLocaleString()}</div>
          <div>Duration: {scanStatus.duration} seconds</div>
          <button onClick={() => getScanResults(domain, scanId)}>
            View Results
          </button>
        </div>
      )}
      
      {scanStatus.status === 'failed' && (
        <div className="error-info">
          <div>Scan failed: {scanStatus.error}</div>
        </div>
      )}
    </div>
  );
}

export default ScanProgress;
```

## Complete Workflow Example

Here's a complete workflow for initiating and tracking a scan:

```javascript
// 1. Check for active scans first
const activeScan = await getActiveScan(domain);

if (activeScan) {
  // There's already an active scan, show its progress
  showScanProgress(domain, activeScan.scan_id);
} else {
  // Start a new scan
  try {
    const scanData = await startScan(domain);
    showScanProgress(domain, scanData.scan_id);
  } catch (error) {
    showError(error.message);
  }
}

// Function to display scan progress (implementation depends on your UI framework)
function showScanProgress(domain, scanId) {
  // For React, render the ScanProgress component
  // For other frameworks, implement appropriate UI
}
```

## Important Notes

1. The scan status should be polled at regular intervals (e.g., every 5 seconds) until the scan is completed or fails.
2. Only one scan can be active for a domain at a time. Attempting to start a new scan while one is in progress will result in a 409 Conflict response.
3. Scan results are available even after the scan is completed, as long as you have the scan_id.
4. All API endpoints require proper authentication (not shown in examples).
