import { Router } from 'express';
import { WPSecAPI } from '../services/wpsec';
import redis from '../config/redis';
import { prisma } from '../config/db';
import { ScanResults } from '../types';

const router = Router();

// Start a new scan
router.post('/start-scan', async (req, res) => {
  try {
    const { domain, websiteId } = req.body;

    if (!domain || !websiteId) {
      return res.status(400).json({ error: 'Domain and websiteId are required' });
    }

    const wpsec = new WPSecAPI(domain, websiteId);
    const { scan_id } = await wpsec.startScan();

    // Store scan information in Redis
    await redis.set(`active_scan:${domain}`, JSON.stringify({
      domain,
      websiteId,
      scanId: scan_id,
      status: 'scanning',
      startedAt: new Date().toISOString()
    }));

    res.json({ scan_id });
  } catch (error) {
    console.error('Error starting scan:', error);
    res.status(500).json({ error: 'Failed to start scan' });
  }
});

// Get scan status
router.get('/scan-status', async (req, res) => {
  try {
    const { domain, scanId } = req.query;

    if (!domain || !scanId) {
      return res.status(400).json({ error: 'Domain and scanId are required' });
    }

    const activeScanData = await redis.get(`active_scan:${domain}`);
    if (!activeScanData) {
      return res.status(404).json({ error: 'No active scan found' });
    }

    const activeScan = JSON.parse(activeScanData);
    const wpsec = new WPSecAPI(domain as string, activeScan.websiteId);
    const status = await wpsec.getScanStatus(scanId as string);

    res.json(status);
  } catch (error) {
    console.error('Error fetching scan status:', error);
    res.status(500).json({ error: 'Failed to fetch scan status' });
  }
});

// Get scan results
router.get('/scan-results', async (req, res) => {
  try {
    const { domain, scanId } = req.query;

    if (!domain || !scanId) {
      return res.status(400).json({ error: 'Domain and scanId are required' });
    }

    const activeScanData = await redis.get(`active_scan:${domain}`);
    if (!activeScanData) {
      return res.status(404).json({ error: 'No active scan found' });
    }

    const activeScan = JSON.parse(activeScanData);
    const wpsec = new WPSecAPI(domain as string, activeScan.websiteId);
    const results = await wpsec.getScanResults(scanId as string);

    res.json(results);
  } catch (error) {
    console.error('Error fetching scan results:', error);
    res.status(500).json({ error: 'Failed to fetch scan results' });
  }
});

// Mark scan as completed and update database
router.post('/mark-scan-completed', async (req, res) => {
  try {
    const { domain, scanId } = req.body;

    if (!domain || !scanId) {
      return res.status(400).json({ error: 'Domain and scanId are required' });
    }

    const activeScanData = await redis.get(`active_scan:${domain}`);
    if (!activeScanData) {
      return res.status(404).json({ error: 'No active scan found' });
    }

    const activeScan = JSON.parse(activeScanData);
    const wpsec = new WPSecAPI(domain, activeScan.websiteId);

    // Fetch final results
    const results = await wpsec.getScanResults(scanId);

    // Update database
    await prisma.website.update({
      where: { id: activeScan.websiteId },
      data: {
        filesystem_data: results as any,
        last_scan_at: new Date()
      }
    });

    // Update Redis
    await redis.set(`active_scan:${domain}`, JSON.stringify({
      ...activeScan,
      status: 'completed',
      completedAt: new Date().toISOString()
    }));

    res.json({ success: true });
  } catch (error) {
    console.error('Error marking scan as completed:', error);
    res.status(500).json({ error: 'Failed to mark scan as completed' });
  }
});

export default router;
