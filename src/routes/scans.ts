import { Router } from 'express';
import { WPSecAPI } from '../services/wpsec';
import { ScanStore } from '../services/scan-store';
import type { ScanStartResponse, ScanStatus, ScanResults, QuarantineResponse, QuarantineListResponse, QuarantineRestoreResponse, BatchOperationResponse } from '../types/wpsec';
import { getWebsiteByDomain, createWebsiteScanResult } from '../config/db';
import { logger } from '../services/logger';

const router = Router();

// Start a new scan
router.post('/:domain/start', async (req, res) => {
  try {
    const { domain } = req.params;

    logger.debug({
      message: 'Starting new scan',
      domain,
      body: req.body
    }, {
      component: 'scan-controller',
      event: 'scan_start_request'
    });
    
    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Check if there's already an active scan
    logger.debug({
      message: 'Checking for active scan',
      domain
    }, {
      component: 'scan-controller',
      event: 'check_active_scan'
    });

    const activeScan = await ScanStore.getActiveScan(domain);
    if (activeScan) {
      logger.info({
        message: 'Active scan already exists',
        domain,
        activeScanId: activeScan.scan_id
      }, {
        component: 'scan-controller',
        event: 'scan_already_active'
      });
      return res.status(409).json({ error: 'A scan is already in progress', scan_id: activeScan.scan_id });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Start scan
    logger.debug({
      message: 'Initiating scan with WPSec API',
      domain
    }, {
      component: 'scan-controller',
      event: 'wpsec_scan_start'
    });

    const scanData = await api.startScan();
    
    // Create initial scan record in database
    try {
      await createWebsiteScanResult(website.id, {
        scan_id: scanData.scan_id,
        infected_files: 0,
        total_files: 0,
        started_at: new Date(scanData.started_at),
        completed_at: new Date(0), // Will be updated when scan completes
        duration: 0,
        status: 'pending'
      });

      logger.info({
        message: 'Initial scan record created in database',
        domain,
        scanId: scanData.scan_id,
        websiteId: website.id
      }, {
        component: 'scan-controller',
        event: 'scan_record_created'
      });
    } catch (dbError) {
      logger.error({
        message: 'Failed to create initial scan record',
        error: dbError instanceof Error ? dbError : new Error('Unknown database error'),
        domain,
        scanId: scanData.scan_id
      }, {
        component: 'scan-controller',
        event: 'scan_record_error'
      });
      // Continue even if database insert fails
    }
    
    logger.info({
      message: 'Scan started successfully',
      domain,
      scanId: scanData.scan_id
    }, {
      component: 'scan-controller',
      event: 'scan_started'
    });

    res.json(scanData);
  } catch (error: any) {
    const errorDomain = req.params.domain;
    logger.error({
      message: 'Error starting scan',
      error,
      domain: errorDomain
    }, {
      component: 'scan-controller',
      event: 'scan_start_error'
    });
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
  }
});

// Get scan status
router.get('/:domain/status/:scanId', async (req, res) => {
  try {
    const { domain, scanId } = req.params;

    logger.debug({
      message: 'Getting scan status',
      domain,
      scanId
    }, {
      component: 'scan-controller',
      event: 'get_scan_status'
    });

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Get scan status
    logger.debug({
      message: 'Fetching scan status from WPSec API',
      domain,
      scanId
    }, {
      component: 'scan-controller',
      event: 'fetch_scan_status'
    });

    const status = await api.getScanStatus(scanId);

    logger.info({
      message: 'Scan status retrieved',
      domain,
      scanId,
      status: status.status,
      progress: status.progress
    }, {
      component: 'scan-controller',
      event: 'scan_status_retrieved'
    });

    res.json(status);
  } catch (error) {
    console.error('Error getting scan status:', error);
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
  }
});

// Get scan results
router.get('/:domain/results/:scanId', async (req, res) => {
  try {
    const { domain, scanId } = req.params;

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Get scan results
    logger.debug({
      message: 'Fetching scan results from WPSec API',
      domain,
      scanId
    }, {
      component: 'scan-controller',
      event: 'fetch_scan_results'
    });

    const results = await api.getScanResults(scanId);

    logger.info({
      message: 'Scan results retrieved',
      domain,
      scanId,
      totalIssues: (results as any).issues?.length || 0,
      totalFiles: (results as any).files?.length || 0
    }, {
      component: 'scan-controller',
      event: 'scan_results_retrieved'
    });

    res.json(results);
  } catch (error) {
    console.error('Error getting scan results:', error);
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
  }
});

// Get active scan for a domain
router.get('/:domain/active', async (req, res) => {
  try {
    const { domain } = req.params;

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Get active scan
    logger.debug({
      message: 'Checking for active scan',
      domain
    }, {
      component: 'scan-controller',
      event: 'check_active_scan'
    });

    const activeScan = await ScanStore.getActiveScan(domain);
    if (!activeScan) {
      logger.info({
        message: 'No active scan found',
        domain
      }, {
        component: 'scan-controller',
        event: 'no_active_scan'
      });
      return res.status(404).json({ error: 'No active scan found' });
    }

    res.json(activeScan);
  } catch (error) {
    console.error('Error getting active scan:', error);
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
  }
});

// Quarantine a single file
router.post('/:domain/quarantine', async (req, res) => {
  try {
    const { domain } = req.params;
    const { file_path } = req.body;

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Quarantine file
    logger.debug({
      message: 'Quarantining file',
      domain,
      filePath: file_path
    }, {
      component: 'scan-controller',
      event: 'quarantine_file'
    });

    const result = await api.quarantineFile(file_path);

    logger.info({
      message: 'File quarantined successfully',
      domain,
      filePath: file_path,
      quarantineId: result.quarantine_id
    }, {
      component: 'scan-controller',
      event: 'file_quarantined'
    });

    res.json(result);
  } catch (error) {
    console.error('Error quarantining file:', error);
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
  }
});

// Get quarantined files
router.get('/:domain/quarantine', async (req, res) => {
  try {
    const { domain } = req.params;

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Get quarantined files
    const files = await api.getQuarantinedFiles();
    res.json(files);
  } catch (error) {
    console.error('Error getting quarantined files:', error);
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
  }
});

// Restore quarantined file
router.post('/:domain/quarantine/restore', async (req, res) => {
  try {
    const { domain } = req.params;
    const { quarantine_id } = req.body;

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Restore file
    const result = await api.restoreQuarantinedFile(quarantine_id);
    res.json(result);
  } catch (error) {
    console.error('Error restoring quarantined file:', error);
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
  }
});

// Batch delete/quarantine files
router.post('/:domain/quarantine/batch', async (req, res) => {
  try {
    const { domain } = req.params;
    const { operation, files } = req.body;

    // Validate operation
    if (!['delete', 'quarantine'].includes(operation)) {
      return res.status(400).json({ error: 'Invalid operation. Must be either "delete" or "quarantine".' });
    }

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Process batch operation
    const result = await api.batchFileOperation(operation, files);
    res.json(result);
  } catch (error) {
    console.error('Error processing batch operation:', error);
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
  }
});

export default router;
