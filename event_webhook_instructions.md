# WPFort Event Webhook Instructions

This document explains how to use the WPFort Pusher webhook to broadcast events to clients.

## Server-Side Implementation

The server implements a webhook endpoint that:

1. Receives events via POST requests to `/api/events/create`
2. Extracts the domain, event, and data from the request body
3. Looks up the website_id for the given domain (using UUID as per requirements)
4. Broadcasts the event to a channel named after the website_id

### ORIGINS ###
wpsec (the plugin)
wpfort_server
wpfort_workers
wpfort_frontend

### VERTICALS ###
wpcore_layer
filesystem_layer
application_layer
firewall_layer
backup
operator


### WP CORE LAYER EVENTS ###
## WP CORE LAYER: DATA STRUCTURE
{
    "event": "[one of the wpcore events]",
    "data": {
        "origin": "wpsec/backend/worker/frontend",
        "vertical": "wpcore_layer",
        "status": "success",
        "message": "WordPress core reinstall started",
        "operation_id": "wpsec_core_reinstall_685cac1d3fe1f9.94536193",
        "version": "current",
        "started_at": "2025-06-26 02:10:37",
        "check_status_endpoint": "https://dev.wptech.group/wp-json/wpsec/v1/core-reinstall?operation_id=wpsec_core_reinstall_685cac1d3fe1f9.94536193"
    }
}

## WP CORE LAYER: EVENTS
wpcore_layer.core_reinstall.started
wpcore_layer.core_reinstall.completed
wpcore_layer.core_reinstall.failed
wpcore_layer.core_check.started
wpcore_layer.core_check.completed
wpcore_layer.permissions_fix.completed
wpcore_layer.permissions_fix.failed

### FILESYSTEM LAYER EVENTS
## FILESYSTEM LAYER: DATA STRUCTURE
{
    "event": "[one of the filesystem events]",
    "data": {
        "origin": "wpsec/backend/worker/frontend",
        "vertical": "filesystem_layer",
        "status": "success",
        "message": "Deep scan started",
        "operation_id": "wpsec_filesystem_scan_685cac1d3fe1f9.94536193",
        "started_at": "2025-06-26 02:10:37",
        "check_status_endpoint": "https://dev.wptech.group/wp-json/wpsec/v1/filesystem-scan?operation_id=wpsec_filesystem_scan_685cac1d3fe1f9.94536193"
    }
}

## FILESYSTEM LAYER: EVENTS
filesystem_layer.filesystem_scan.started
filesystem_layer.filesystem_scan.completed
filesystem_layer.filesystem_scan.failed
filesystem_layer.file_quarantine.completed
filesystem_layer.file_quarantine_restore.completed
filesystem_layer.file_quarantine_restore.failed
filesystem_layer.file_quarantine.failed
filesystem_layer.file_whitelist.completed
filesystem_layer.file_whitelist_remove.completed
filesystem_layer.file_whitelist_remove.failed
filesystem_layer.file_whitelist.failed
filesystem_layer.file_restore.completed
filesystem_layer.file_restore.failed
filesystem_layer.file_delete.completed
filesystem_layer.file_delete.failed

### APPLICATION LAYER EVENTS
## APPLICATION LAYER: DATA STRUCTURE
{
    "event": "[one of the application events]",
    "data": {
        "origin": "wpsec/backend/worker/frontend",
        "vertical": "application_layer",
        "status": "success",
        "message": "Plugin updated",
        "metadata": {
            "plugin_name": "plugin_name",
            "plugin_version": "plugin_version",
            "plugin_status": "active"
        }
    }
}

## APPLICATION LAYER: EVENTS
application_layer.plugins.update.started
application_layer.plugins.update.completed
application_layer.plugins.update.failed
application_layer.plugins.activated
application_layer.plugins.deactivated
application_layer.vulnerabilities_scan.started
application_layer.vulnerabilities_scan.completed
application_layer.vulnerabilities_scan.failed


### FIREWALL LAYER EVENTS
## FIREWALL LAYER: DATA STRUCTURE
{
    "event": "[one of the firewall events]",
    "data": {
        "origin": "wpsec/backend/worker/frontend",
        "vertical": "firewall_layer",
        "status": "success",
        "message": "Attack blocked",
        "metadata": {
            "attack_type": "SQL Injection",
            "attack_source": "127.0.0.1",
            "attack_target": "/wp-admin/admin-ajax.php",
            "attack_time": "2025-06-26 02:10:37"
        }
    }
}

## FIREWALL LAYER: EVENTS
network_layer.firewall.attacks.blocked
network_layer.firewall.blacklist.updated
network_layer.firewall.whitelist.updated
network_layer.firewall.toggled.on
network_layer.firewall.toggled.off

### BACKUP LAYER EVENTS
## BACKUP LAYER: DATA STRUCTURE
{
    "event": "[one of the backup events]",
    "data": {
        "origin": "wpsec/backend/worker/frontend",
        "vertical": "backup",
        "status": "success",
        "message": "Backup completed",
        "metadata": {
            "backup_id": "backup_id",
            "backup_type": "full",
            "backup_size": "100MB",
            "backup_time": "2025-06-26 02:10:37"
        }
    }
}

## BACKUP LAYER: EVENTS
backup.backup.started
backup.backup.completed
backup.backup.failed
backup.restore.started
backup.restore.completed
backup.restore.failed

### OPERATOR LAYER EVENTS
## OPERATOR LAYER: DATA STRUCTURE
{
    "event": "[one of the operator events]",
    "data": {
        "origin": "wpsec/backend/worker/frontend",
        "vertical": "operator",
        "status": "success",
        "message": "Assessment completed",
        "metadata": {
            "assessment_id": "assessment_id",
            "assessment_time": "2025-06-26 02:10:37"
            "metadata": {}
        }
    }
}

## OPERATOR LAYER: EVENTS
operator.assessment.started
operator.assessment.completed
operator.assessment.failed
operator.action.started
operator.action.completed
operator.action.failed


## Testing the Endpoint

You can test the endpoint using curl:

```bash
curl -X POST http://[wpfort-server]:3001/api/events/create \
  -H "Content-Type: application/json" \
  -H "x-wpfort-token: 123123123" \
  -d '{"domain": "sub2.test-wpworld.uk", "event": "wpcore_layer.core_reinstall.started", "data": {"event": "wpcore_layer.core_reinstall.started",
            "data": {
            "origin": "wpsec/backend/worker/frontend",
            "vertical": "wpcore_layer",
            "status": "success",
            "message": "WordPress core reinstall started",
            "operation_id": "wpsec_core_reinstall_685cac1d3fe1f9.94536193",
            "version": "current",
            "started_at": "2025-06-26 02:10:37",
            "check_status_endpoint": "https://dev.wptech.group/wp-json/wpsec/v1/core-reinstall?operation_id=wpsec_core_reinstall_685cac1d3fe1f9.94536193"
        }
  }}'
```

Example response:

```json
{
  "success": true,
  "message": "Event created successfully",
  "websiteId": "dc50c5ec-d5fe-4040-86f7-9615d45df55e",
  "channel": "dc50c5ec-d5fe-4040-86f7-9615d45df55e",
  "event": "wpcore_layer.core_reinstall.started"
}
```

