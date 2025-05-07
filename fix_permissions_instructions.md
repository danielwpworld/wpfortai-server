# Fix Permissions API Guide

## Overview

The Fix Permissions API allows you to correct file and directory permissions on WordPress websites. Improper file permissions can be a security risk, potentially allowing unauthorized access to sensitive files or preventing legitimate operations.

## API Endpoint

```
POST /:domain/fix-permissions
```

## Request Options

The API supports two modes of operation:

### 1. Fix All Permissions

To fix permissions across the entire WordPress installation:

```json
{
  "fix_all": true
}
```

### 2. Fix Specific Path

To fix permissions for a specific file or directory:

```json
{
  "path": "/path/to/file/or/directory",
  "type": "file",
  "recursive": false
}
```

#### Parameters:

| Parameter | Type    | Required | Description |
|-----------|---------|----------|-------------|
| path      | string  | Yes      | Path to the file or directory to fix |
| type      | string  | Yes      | Must be either "file" or "directory" |
| recursive | boolean | No       | If true and type is "directory", fixes permissions recursively for all contents. Default: false |

## Response Format

### Success Response

```json
{
  "status": "success",
  "message": "Permissions fixed successfully",
  "details": {
    "files_updated": 5,
    "directories_updated": 2
  }
}
```

### Error Response

```json
{
  "error": "Error message details"
}
```

## Common Error Codes

| Status Code | Description |
|-------------|-------------|
| 400         | Bad request (missing required parameters) |
| 404         | Website not found |
| 500         | Server error |

## Frontend Implementation Guidelines

### 1. Global Fix Permissions Button

Implement a "Fix All Permissions" button in the security dashboard:

```typescript
const fixAllPermissions = async (domain) => {
  try {
    setLoading(true);
    const response = await fetch(`/api/${domain}/fix-permissions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        fix_all: true
      })
    });
    
    const result = await response.json();
    if (response.ok) {
      showSuccessNotification('Permissions fixed successfully');
    } else {
      showErrorNotification(result.error || 'Failed to fix permissions');
    }
  } catch (error) {
    showErrorNotification('Error connecting to server');
    console.error('Fix permissions error:', error);
  } finally {
    setLoading(false);
  }
};
```

### 2. File/Directory Specific Fix

When displaying file information, add a "Fix Permissions" option:

```typescript
const fixFilePermissions = async (domain, filePath) => {
  try {
    setLoading(true);
    const response = await fetch(`/api/${domain}/fix-permissions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        path: filePath,
        type: 'file'
      })
    });
    
    const result = await response.json();
    if (response.ok) {
      showSuccessNotification('File permissions fixed');
    } else {
      showErrorNotification(result.error || 'Failed to fix file permissions');
    }
  } catch (error) {
    showErrorNotification('Error connecting to server');
    console.error('Fix permissions error:', error);
  } finally {
    setLoading(false);
  }
};
```

### 3. Directory Recursive Fix

For directories, provide an option to fix permissions recursively:

```typescript
const fixDirectoryPermissions = async (domain, dirPath, recursive = false) => {
  try {
    setLoading(true);
    const response = await fetch(`/api/${domain}/fix-permissions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        path: dirPath,
        type: 'directory',
        recursive: recursive
      })
    });
    
    const result = await response.json();
    if (response.ok) {
      showSuccessNotification(
        recursive 
          ? 'Directory and all contents permissions fixed' 
          : 'Directory permissions fixed'
      );
    } else {
      showErrorNotification(result.error || 'Failed to fix directory permissions');
    }
  } catch (error) {
    showErrorNotification('Error connecting to server');
    console.error('Fix permissions error:', error);
  } finally {
    setLoading(false);
  }
};
```

### 4. UI Components

#### Fix All Permissions Button

```jsx
<Button 
  variant="primary"
  onClick={() => fixAllPermissions(domain)}
  disabled={loading}
>
  {loading ? 'Fixing Permissions...' : 'Fix All Permissions'}
</Button>
```

#### File Context Menu

```jsx
<ContextMenu>
  <MenuItem onClick={() => fixFilePermissions(domain, file.path)}>
    Fix Permissions
  </MenuItem>
  {/* Other file actions */}
</ContextMenu>
```

#### Directory Context Menu

```jsx
<ContextMenu>
  <MenuItem onClick={() => fixDirectoryPermissions(domain, directory.path, false)}>
    Fix Directory Permissions
  </MenuItem>
  <MenuItem onClick={() => fixDirectoryPermissions(domain, directory.path, true)}>
    Fix Directory & Contents Permissions
  </MenuItem>
  {/* Other directory actions */}
</ContextMenu>
```

## Best Practices

1. **Progress Indication**: For large sites, fixing all permissions may take time. Implement a loading indicator and consider polling for status updates.

2. **Error Handling**: Provide clear error messages to users when permission fixes fail.

3. **Confirmation Dialogs**: Consider adding confirmation dialogs before executing recursive permission fixes on large directories.

4. **Permissions Explanation**: Include information about what permissions will be applied (e.g., 644 for files, 755 for directories).

5. **Audit Logging**: Log permission changes for security auditing purposes.

## Important Notes

1. **UUID Handling**: Remember that the `website_id` field is a UUID type, not an integer. Ensure proper UUID handling in your frontend code when working with website IDs.

2. **Permission Requirements**: The WordPress site must have sufficient server permissions to change file/directory permissions. This typically requires PHP to be running as the same user that owns the files or with sufficient privileges.

3. **Security Considerations**: Fixing permissions should be done cautiously, as incorrect permissions can create security vulnerabilities. The API implements best practices for WordPress file permissions.
