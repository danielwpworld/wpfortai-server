import { Router } from 'express';
import { WPSecAPI } from '../services/wpsec';
import { getWebsiteByDomain } from '../config/db';

const router = Router();

// Start a backup
router.post('/:domain/start', async (req, res) => {
  try {
    const { domain } = req.params;
    const { type, incremental } = req.body;

    if (!type) {
      return res.status(400).json({ error: 'type is required' });
    }

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Start backup
    const result = await api.startBackup(type, incremental);
    res.json(result);
  } catch (error) {
    console.error('Error starting backup:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get backup status
router.get('/:domain/status/:backupId', async (req, res) => {
  try {
    const { domain, backupId } = req.params;

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Get backup status
    const status = await api.getBackupStatus(backupId);
    res.json(status);
  } catch (error) {
    console.error('Error getting backup status:', error);
    res.status(500).json({ error: error.message });
  }
});

// List backups
router.get('/:domain/list', async (req, res) => {
  try {
    const { domain } = req.params;

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // List backups
    const backups = await api.listBackups();
    res.json(backups);
  } catch (error) {
    console.error('Error listing backups:', error);
    res.status(500).json({ error: error.message });
  }
});

// Restore backup
router.post('/:domain/restore/:backupId', async (req, res) => {
  try {
    const { domain, backupId } = req.params;

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Restore backup
    const result = await api.restoreBackup(backupId);
    res.json(result);
  } catch (error) {
    console.error('Error restoring backup:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get restore status
router.get('/:domain/restore/:restoreId/status', async (req, res) => {
  try {
    const { domain, restoreId } = req.params;

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Get restore status
    const status = await api.getRestoreStatus(restoreId);
    res.json(status);
  } catch (error) {
    console.error('Error getting restore status:', error);
    res.status(500).json({ error: error.message });
  }
});

export default router;
