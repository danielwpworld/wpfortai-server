import { Router } from 'express';
import { WPSecAPI } from '../services/wpsec';
import { ScanStore } from '../services/scan-store';
import { getWebsiteByDomain, createWebsiteScanResult, createScanDetection } from '../config/db';

const router = Router();

// Site Information
router.get('/site-info/:domain', async (req, res) => {
  try {
    const api = new WPSecAPI(req.params.domain);
    const info = await api.getSiteInfo();
    res.json(info);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Vulnerabilities
router.get('/vulnerabilities/:domain', async (req, res) => {
  try {
    const api = new WPSecAPI(req.params.domain);
    const vulnerabilities = await api.getVulnerabilities();
    res.json(vulnerabilities);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Scanning
router.post('/scan/:domain', async (req, res) => {
  try {
    const api = new WPSecAPI(req.params.domain);
    const result = await api.startScan();
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/scan/:domain/:scanId/status', async (req, res) => {
  try {
    const api = new WPSecAPI(req.params.domain);
    const status = await api.getScanStatus(req.params.scanId);
    res.json(status);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/scan/:domain/:scanId/results', async (req, res) => {
  try {
    const api = new WPSecAPI(req.params.domain);
    const results = await api.getScanResults(req.params.scanId);
    res.json(results);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Firewall Management
router.post('/firewall/:domain/toggle', async (req, res) => {
  try {
    const api = new WPSecAPI(req.params.domain);
    await api.toggleFirewall(req.body.active);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/firewall/:domain/status', async (req, res) => {
  try {
    const api = new WPSecAPI(req.params.domain);
    const status = await api.getFirewallStatus();
    res.json(status);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/firewall/:domain/logs', async (req, res) => {
  try {
    const api = new WPSecAPI(req.params.domain);
    const period = req.query.period ? parseInt(req.query.period as string) : undefined;
    const logs = await api.getFirewallLogs(period);
    res.json(logs);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/firewall/:domain/whitelist', async (req, res) => {
  try {
    const api = new WPSecAPI(req.params.domain);
    await api.whitelistFirewallIP(req.body.ip, req.body.action);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Backup Management
router.post('/backup/:domain/start', async (req, res) => {
  try {
    const api = new WPSecAPI(req.params.domain);
    const result = await api.startBackup(req.body.type, req.body.incremental);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/backup/:domain/status/:backupId', async (req, res) => {
  try {
    const api = new WPSecAPI(req.params.domain);
    const status = await api.getBackupStatus(req.params.backupId);
    res.json(status);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/backup/:domain/list', async (req, res) => {
  try {
    const api = new WPSecAPI(req.params.domain);
    const backups = await api.listBackups();
    res.json(backups);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/backup/:domain/restore/:backupId', async (req, res) => {
  try {
    const api = new WPSecAPI(req.params.domain);
    const result = await api.restoreBackup(req.params.backupId);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/backup/:domain/restore/:restoreId/status', async (req, res) => {
  try {
    const api = new WPSecAPI(req.params.domain);
    const status = await api.getRestoreStatus(req.params.restoreId);
    res.json(status);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// WordPress Core Management
router.get('/core/:domain/check', async (req, res) => {
  try {
    const api = new WPSecAPI(req.params.domain);
    const result = await api.checkCoreIntegrity();
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/core/:domain/update-all', async (req, res) => {
  try {
    const api = new WPSecAPI(req.params.domain);
    await api.updateAll();
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/core/:domain/update-items', async (req, res) => {
  try {
    const api = new WPSecAPI(req.params.domain);
    await api.updateItems(req.body.type, req.body.items);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// File Management
router.post('/whitelist/:domain', async (req, res) => {
  try {
    const api = new WPSecAPI(req.params.domain);
    await api.whitelistFile(req.body.file_path, req.body.reason, req.body.added_by);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/whitelist/:domain/list', async (req, res) => {
  try {
    const api = new WPSecAPI(req.params.domain);
    const includeDetails = req.query.include_details === '1';
    const verifyIntegrity = req.query.verify_integrity === '1';
    const files = await api.getWhitelistedFiles(includeDetails, verifyIntegrity);
    res.json(files);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/whitelist/:domain/remove', async (req, res) => {
  try {
    const api = new WPSecAPI(req.params.domain);
    await api.removeWhitelistedFile(req.body.file_path);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/whitelist/:domain/verify', async (req, res) => {
  try {
    const api = new WPSecAPI(req.params.domain);
    const result = await api.verifyWhitelistIntegrity();
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/whitelist/:domain/cleanup', async (req, res) => {
  try {
    const api = new WPSecAPI(req.params.domain);
    await api.cleanupWhitelist();
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Webhook for scan progress updates
router.post('/webhook/scan-progress', async (req, res) => {
  try {
    const { scan_id, status, progress } = req.body;
    if (!scan_id) {
      return res.status(400).json({ error: 'scan_id is required' });
    }

    // Get scan data from Redis
    const scanData = await ScanStore.getScan(scan_id);
    if (!scanData) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    // Update scan status in Redis
    const existingScan = await ScanStore.getScan(scan_id);
    if (!existingScan) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    await ScanStore.updateScanStatus(scan_id, {
      ...existingScan,
      status: status || existingScan.status,
      progress: progress ?? existingScan.progress ?? 0
    });

    res.json({ success: true });
  } catch (error) {
    console.error('Error processing scan progress webhook:', error);
    res.status(500).json({ error: error.message });
  }
});

// Webhook for scan completion
router.post('/webhook/scan-complete', async (req, res) => {
  try {
    const { scan_id } = req.body;
    if (!scan_id) {
      return res.status(400).json({ error: 'scan_id is required' });
    }

    // Get scan data from Redis
    const scanData = await ScanStore.getScan(scan_id);
    if (!scanData) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    // Get website from database
    const website = await getWebsiteByDomain(scanData.domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(scanData.domain);

    // Fetch scan results
    const results = await api.getScanResults(scan_id);

    // Store scan results in database
    await createWebsiteScanResult(website.id, {
      scan_id,
      infected_files: parseInt(results.infected_count),
      total_files: parseInt(results.total_files_scanned),
      started_at: new Date(results.started_at),
      completed_at: new Date(results.completed_at),
      duration: parseInt(results.duration)
    });

    // Store detections in database
    for (const file of results.infected_files) {
      for (const detection of file.detections) {
        await createScanDetection(website.id, scan_id, {
          file_path: file.file_path,
          threat_score: file.threat_score,
          confidence: file.confidence,
          detection_type: detection.type,
          severity: detection.severity,
          description: detection.description,
          file_hash: detection.file_hash,
          file_size: file.file_size,
          context_type: file.context.type,
          risk_level: file.context.risk_level
        });
      }
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Error processing scan completion webhook:', error);
    res.status(500).json({ error: error.message });
  }
});

export default router;
