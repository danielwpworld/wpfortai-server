# WPFort Batch Operations Guide

This document provides instructions on how to use the batch operations for quarantining and deleting files in WPFort.

## Table of Contents

1. [Overview](#overview)
2. [Batch Quarantine](#batch-quarantine)
3. [Batch Delete](#batch-delete)
4. [API Endpoints](#api-endpoints)
5. [Request Format](#request-format)
6. [Response Format](#response-format)
7. [Error Handling](#error-handling)

## Overview

WPFort provides batch operations that allow you to quarantine or delete multiple files in a single API call. This is particularly useful when dealing with multiple infected files detected during a scan.

## Batch Quarantine

Batch quarantine allows you to move multiple suspicious files to a quarantine area where they can be safely stored without affecting the website's functionality.

### When to use batch quarantine:

- When you have identified multiple malicious files that need to be isolated
- When you want to temporarily remove files from the website without permanently deleting them
- When you need to review suspicious files before deciding to delete them

### What happens during batch quarantine:

1. Files are moved to a secure quarantine location
2. Original file paths are recorded for potential restoration
3. Database records are updated to reflect the quarantined status
4. Scan detection records are updated with 'quarantined' status

## Batch Delete

Batch delete allows you to permanently remove multiple files from the website.

### When to use batch delete:

- When you have confirmed that multiple files are malicious and should be removed
- When you want to clean up quarantined files that are no longer needed
- When you need to remove multiple infected files in one operation

### What happens during batch delete:

1. For regular files (not quarantined):
   - Files are permanently deleted from the filesystem
   - Scan detection records are updated with 'deleted' status
   - Entries are created in the `deleted_detections` table

2. For quarantined files:
   - Files are deleted from the quarantine area
   - Records are moved from `quarantined_detections` to `deleted_detections`
   - Scan detection records are updated with 'deleted' status

## API Endpoints

### Batch Operation Endpoint

```
POST /:domain/batch-operation
```

This endpoint handles both quarantine and delete operations.

## Request Format

### Request Body

```json
{
  "operation": "quarantine|delete",
  "files": [
    { "file_path": "/path/to/file1.php" },
    { "file_path": "/path/to/file2.php" }
  ],
  "scan_detection_ids": [123, 456],  // Optional: IDs from scan_detections table
  "quarantine_ids": ["q123", "q456"] // Optional: Only for deleting quarantined files
}
```

### Parameters

- `operation`: (Required) Must be either "quarantine" or "delete"
- `files`: (Required) Array of objects, each containing a `file_path` property
- `scan_detection_ids`: (Optional) Array of scan detection IDs corresponding to the files
- `quarantine_ids`: (Optional) Array of quarantine IDs when deleting quarantined files

### Important Notes:

- The arrays should be in the same order - i.e., `files[0]` corresponds to `scan_detection_ids[0]` and `quarantine_ids[0]`
- When deleting quarantined files, provide the `quarantine_ids` array
- When quarantining files, you can optionally provide `scan_detection_ids` to update their status

## Response Format

```json
{
  "status": "success",
  "results": {
    "total": 2,
    "success": [
      {
        "file_path": "/path/to/file1.php",
        "result": {
          "quarantine_id": "q789",  // Only for quarantine operations
          "quarantine_path": "/quarantine/path/file1.php",  // Only for quarantine operations
          "success": true
        }
      },
      {
        "file_path": "/path/to/file2.php",
        "result": {
          "quarantine_id": "q790",  // Only for quarantine operations
          "quarantine_path": "/quarantine/path/file2.php",  // Only for quarantine operations
          "success": true
        }
      }
    ],
    "failed": []
  }
}
```

### Response Fields

- `status`: Overall status of the operation ("success" or "error")
- `results`: Object containing details about the operation
  - `total`: Total number of files processed
  - `success`: Array of successfully processed files with their results
  - `failed`: Array of files that failed to process

## Error Handling

If the batch operation encounters errors, the response will include details about which files failed:

```json
{
  "status": "partial",
  "results": {
    "total": 2,
    "success": [
      {
        "file_path": "/path/to/file1.php",
        "result": { "success": true }
      }
    ],
    "failed": [
      {
        "file_path": "/path/to/file2.php",
        "error": "File not found"
      }
    ]
  }
}
```

### Common Error Scenarios:

1. **File not found**: The specified file does not exist
2. **Permission denied**: The system lacks permission to access or modify the file
3. **Invalid quarantine ID**: When deleting quarantined files, the provided quarantine ID is invalid
4. **Database error**: Error updating database records

## Examples

### Example 1: Batch Quarantine

```json
// Request
POST /example.com/batch-operation
{
  "operation": "quarantine",
  "files": [
    { "file_path": "/var/www/html/wp-content/themes/theme1/infected.php" },
    { "file_path": "/var/www/html/wp-content/plugins/plugin1/malware.php" }
  ],
  "scan_detection_ids": [123, 456]
}

// Response
{
  "status": "success",
  "results": {
    "total": 2,
    "success": [
      {
        "file_path": "/var/www/html/wp-content/themes/theme1/infected.php",
        "result": {
          "quarantine_id": "q123",
          "quarantine_path": "/quarantine/path/infected.php",
          "success": true
        }
      },
      {
        "file_path": "/var/www/html/wp-content/plugins/plugin1/malware.php",
        "result": {
          "quarantine_id": "q124",
          "quarantine_path": "/quarantine/path/malware.php",
          "success": true
        }
      }
    ],
    "failed": []
  }
}
```

### Example 2: Batch Delete (Regular Files)

```json
// Request
POST /example.com/batch-operation
{
  "operation": "delete",
  "files": [
    { "file_path": "/var/www/html/wp-content/themes/theme1/infected.php" },
    { "file_path": "/var/www/html/wp-content/plugins/plugin1/malware.php" }
  ],
  "scan_detection_ids": [123, 456]
}

// Response
{
  "status": "success",
  "results": {
    "total": 2,
    "success": [
      {
        "file_path": "/var/www/html/wp-content/themes/theme1/infected.php",
        "result": { "success": true }
      },
      {
        "file_path": "/var/www/html/wp-content/plugins/plugin1/malware.php",
        "result": { "success": true }
      }
    ],
    "failed": []
  }
}
```

### Example 3: Batch Delete (Quarantined Files)

```json
// Request
POST /example.com/batch-operation
{
  "operation": "delete",
  "files": [
    { "file_path": "/var/www/html/wp-content/themes/theme1/infected.php" },
    { "file_path": "/var/www/html/wp-content/plugins/plugin1/malware.php" }
  ],
  "quarantine_ids": ["q123", "q124"]
}

// Response
{
  "status": "success",
  "results": {
    "total": 2,
    "success": [
      {
        "file_path": "/var/www/html/wp-content/themes/theme1/infected.php",
        "result": { "success": true }
      },
      {
        "file_path": "/var/www/html/wp-content/plugins/plugin1/malware.php",
        "result": { "success": true }
      }
    ],
    "failed": []
  }
}
```
