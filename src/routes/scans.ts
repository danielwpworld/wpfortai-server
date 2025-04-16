import { Router } from 'express';
import { WPSecAPI } from '../services/wpsec';
import { ScanStore } from '../services/scan-store';
import { getWebsiteByDomain } from '../config/db';

const router = Router();

// Start a new scan
router.post('/:domain/start', async (req, res) => {
  try {
    const { domain } = req.params;
    
    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Check if there's already an active scan
    const activeScan = await ScanStore.getActiveScan(domain);
    if (activeScan) {
      return res.status(409).json({ error: 'A scan is already in progress', scan_id: activeScan.scan_id });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Start scan
    const scanData = await api.startScan();
    res.json(scanData);
  } catch (error) {
    console.error('Error starting scan:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get scan status
router.get('/:domain/status/:scanId', async (req, res) => {
  try {
    const { domain, scanId } = req.params;

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Get scan status
    const status = await api.getScanStatus(scanId);
    res.json(status);
  } catch (error) {
    console.error('Error getting scan status:', error);
    res.status(500).json({ error: error.message });
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
    const results = await api.getScanResults(scanId);
    res.json(results);
  } catch (error) {
    console.error('Error getting scan results:', error);
    res.status(500).json({ error: error.message });
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
    const activeScan = await ScanStore.getActiveScan(domain);
    if (!activeScan) {
      return res.status(404).json({ error: 'No active scan found' });
    }

    res.json(activeScan);
  } catch (error) {
    console.error('Error getting active scan:', error);
    res.status(500).json({ error: error.message });
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
    const result = await api.quarantineFile(file_path);
    res.json(result);
  } catch (error) {
    console.error('Error quarantining file:', error);
    res.status(500).json({ error: error.message });
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
    res.status(500).json({ error: error.message });
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
    res.status(500).json({ error: error.message });
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
    res.status(500).json({ error: error.message });
  }
});

export default router;
