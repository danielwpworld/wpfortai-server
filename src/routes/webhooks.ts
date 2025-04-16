import { Router } from 'express';
import { ScanStore } from '../services/scan-store';
import { WPSecAPI } from '../services/wpsec';
import { createWebsiteScanResult, getWebsiteByDomain, createScanDetection } from '../config/db';
import { verifyWebhook } from '../middleware/verify-webhook';
import { WebhookSecrets } from '../services/webhook-secrets';

const router = Router();

// Middleware to verify webhook signatures
router.use(async (req, res, next) => {
  try {
    const scanId = req.body.scan_id;
    if (!scanId) {
      return res.status(400).json({ error: 'scan_id is required' });
    }

    // Get scan data from Redis
    const scanData = await ScanStore.getScan(scanId);
    if (!scanData) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    // Get website
    const website = await getWebsiteByDomain(scanData.domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Get webhook secret
    const secret = await WebhookSecrets.getWebhookSecret(website.id);
    if (!secret) {
      return res.status(401).json({ error: 'No webhook secret configured' });
    }

    // Verify webhook signature
    verifyWebhook(secret)(req, res, next);
  } catch (error) {
    console.error('Error in webhook verification middleware:', error);
    res.status(500).json({ error: error.message });
  }
});

// Webhook for scan progress updates
router.post('/scan-progress', async (req, res) => {
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

// Webhook for scan failed
router.post('/scan-failed', async (req, res) => {
  try {
    const { scan_id, error_message } = req.body;
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

    // Update scan status in Redis
    await ScanStore.updateScanStatus(scan_id, {
      ...scanData,
      status: 'failed',
      error: error_message
    });

    // Store scan failure in database
    await createWebsiteScanResult(website.id, {
      scan_id,
      infected_files: 0,
      total_files: 0,
      started_at: new Date(scanData.started_at || Date.now()),
      completed_at: new Date(),
      duration: 0,
      status: 'failed',
      error_message
    });

    res.json({ success: true });
  } catch (error) {
    console.error('Error processing scan failed webhook:', error);
    res.status(500).json({ error: error.message });
  }
});

// Webhook for scan completion
router.post('/scan-complete', async (req, res) => {
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
