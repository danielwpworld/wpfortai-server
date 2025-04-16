import { Router } from 'express';
import { WPSecAPI } from '../services/wpsec';
import { getWebsiteByDomain } from '../config/db';
import { logger } from '../services/logger';

const router = Router();

// Start a backup
router.post('/:domain/start', async (req, res) => {
  try {
    const { domain } = req.params;
    const { type, incremental } = req.body;

    logger.debug({
      message: 'Starting new backup',
      domain,
      type,
      incremental
    }, {
      component: 'backup-controller',
      event: 'start_backup'
    });

    if (!type) {
      logger.warn({
        message: 'Missing backup type',
        domain
      }, {
        component: 'backup-controller',
        event: 'missing_type'
      });
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
    logger.debug({
      message: 'Initiating backup with WPSec API',
      domain,
      type,
      incremental
    }, {
      component: 'backup-controller',
      event: 'initiate_backup'
    });

    const result = await api.startBackup(type, incremental);

    logger.info({
      message: 'Backup started successfully',
      domain,
      backupId: result.backup_id,
      type,
      incremental
    }, {
      component: 'backup-controller',
      event: 'backup_started'
    });

    res.json(result);
  } catch (error: any) {
    const errorDomain = req.params.domain;
    logger.error({
      message: 'Error starting backup',
      error,
      domain: errorDomain,
      type: req.body.type,
      incremental: req.body.incremental
    }, {
      component: 'backup-controller',
      event: 'backup_start_error'
    });
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
  }
});

// Get backup status
router.get('/:domain/status/:backupId', async (req, res) => {
  try {
    const { domain, backupId } = req.params;

    logger.debug({
      message: 'Getting backup status',
      domain,
      backupId
    }, {
      component: 'backup-controller',
      event: 'get_backup_status'
    });

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Get backup status
    logger.debug({
      message: 'Fetching backup status from WPSec API',
      domain,
      backupId
    }, {
      component: 'backup-controller',
      event: 'fetch_backup_status'
    });

    const status = await api.getBackupStatus(backupId);

    logger.info({
      message: 'Backup status retrieved',
      domain,
      backupId,
      status: status.status,
      progress: status.progress,
      size: (status as any).size
    }, {
      component: 'backup-controller',
      event: 'backup_status_retrieved'
    });

    res.json(status);
  } catch (error: any) {
    const errorDomain = req.params.domain;
    logger.error({
      message: 'Error getting backup status',
      error,
      domain: errorDomain,
      backupId: req.params.backupId
    }, {
      component: 'backup-controller',
      event: 'backup_status_error'
    });
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
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
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
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
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
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
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
  }
});

export default router;
