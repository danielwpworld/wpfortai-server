import { Router } from 'express';
import { WPSecAPI } from '../services/wpsec';
import { getWebsiteByDomain } from '../config/db';

const router = Router();

// Add file to whitelist
router.post('/:domain', async (req, res) => {
  try {
    const { domain } = req.params;
    const { file_path, reason, added_by } = req.body;

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Add file to whitelist
    await api.whitelistFile(file_path, reason, added_by);
    res.json({ success: true });
  } catch (error) {
    console.error('Error adding file to whitelist:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get whitelisted files
router.get('/:domain/files', async (req, res) => {
  try {
    const { domain } = req.params;
    const { include_details, verify_integrity } = req.query;

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Get whitelisted files
    const files = await api.getWhitelistedFiles(
      include_details === '1',
      verify_integrity === '1'
    );
    res.json(files);
  } catch (error) {
    console.error('Error getting whitelisted files:', error);
    res.status(500).json({ error: error.message });
  }
});

// Remove file from whitelist
router.post('/:domain/remove', async (req, res) => {
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

    // Remove file from whitelist
    await api.removeWhitelistedFile(file_path);
    res.json({ success: true });
  } catch (error) {
    console.error('Error removing file from whitelist:', error);
    res.status(500).json({ error: error.message });
  }
});

// Verify whitelist integrity
router.get('/:domain/verify', async (req, res) => {
  try {
    const { domain } = req.params;

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Verify whitelist integrity
    const result = await api.verifyWhitelistIntegrity();
    res.json(result);
  } catch (error) {
    console.error('Error verifying whitelist integrity:', error);
    res.status(500).json({ error: error.message });
  }
});

// Cleanup whitelist
router.post('/:domain/cleanup', async (req, res) => {
  try {
    const { domain } = req.params;

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Cleanup whitelist
    await api.cleanupWhitelist();
    res.json({ success: true });
  } catch (error) {
    console.error('Error cleaning up whitelist:', error);
    res.status(500).json({ error: error.message });
  }
});

export default router;
