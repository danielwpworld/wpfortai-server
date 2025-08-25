Backups module task explained:
- Since the backup processes require code that is not 100% wp.org compliant, we are separating the backup functionality ONLY with a separate pro module. Basically a plugin on its own.
- Latest main plugin version does not contain backup/restore functionality.

What needs to be done?
- Whenever a user goes to the main backup screen/menu, before we show it to them, we need to ping the site to check if the backup module is installed and active, here's how:
GET  https://sub8.test-wpworld.uk/?wpsec_endpoint=backup/status (same auth with the x-api-key we always use).

Example response:
{
    "success": true,
    "data": {
        "module_installed": true,
        "module_active": "1",
        "module_version": "1.0.0",
        "classes_loaded": true,
        "endpoints_available": true,
        "plugin_path": "wpfortai-security-backup/wpfortai-security-backup.php",
        "status": "active",
        "message": "Backup module is installed and fully functional"
    }
}

Or: 
{
    "success": true,
    "data": {
        "module_installed": false,
        "module_active": false,
        "module_version": null,
        "classes_loaded": false,
        "endpoints_available": false,
        "plugin_path": "wpfortai-security-backup/wpfortai-security-backup.php",
        "status": "inactive",
        "message": "Backup module is not available - install WPFort Backup Pro addon"
    }
}

If installed and active, unlock screen and proceed as usual. 

If not active, we need to install and activate it using the following API call:
POST https://sub6.test-wpworld.uk/?wpsec_endpoint=addon/install-backup

Example response:
{
    "success": true,
    "message": "Backup addon installed and activated successfully",
    "status": "installed_and_activated"
}

For a manual option if it fails, they can download it and install as a regular plugin, like so:
https://server.wpfort.ai:4443/wpfortai-security-backup.zip?key=scriptallowed-wpfort


Nothing changed in the way we communicate with backup/restore API after the module is active.