# Quarantine Endpoints

## Quarantine a File
- **Endpoint**: `POST /api/scans/:domain/quarantine`
- **Body**:
  ```json
  {
    "file_path": "<string>",           // required
    "scan_detection_id": "<string>",   // optional
    "scan_finding_id": "<string>"      // optional
  }
  ```
- **Response Body**:
  ```json
  {
    "status": "success" | "error",
    "message": "<string>",
    "file_path": "<string>",
    "quarantine_id": "<string>",
    "original_path": "<string>",
    "quarantine_path": "<string>",
    "timestamp": "<string>",
    // optional: file_size, file_type, file_hash, detection_type
  }
  ```

## List Quarantined Files
- **Endpoint**: `GET /api/scans/:domain/quarantine`
- **Body**: None
- **Response Body**:
  ```json
  {
    "status": "success" | "error",
    "count": <number>,
    "files": [
      {
        "quarantine_id": "<string>",
        "original_path": "<string>",
        "quarantine_path": "<string>",
        "timestamp": "<string>",
        "scan_finding_id": "<string|null>",
        "file_size": <number>,
        "file_type": "<string>",
        "file_hash": "<string|null>",
        "detection_type": "<string>"
      }
      // ...
    ]
  }
  ```

## Restore a Quarantined File
- **Endpoint**: `POST /api/scans/:domain/quarantine/restore`
- **Body**:
  ```json
  {
    "quarantine_id": "<string>"    // required
  }
  ```
- **Response Body**:
  ```json
  {
    "status": "success" | "error",
    "message": "<string>",
    "quarantine_id": "<string>",
    "original_path": "<string>",
    "timestamp": "<string>"
  }
  ```
