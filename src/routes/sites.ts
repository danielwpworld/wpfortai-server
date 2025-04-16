import { Router } from 'express';
import { WPSecAPI } from '../services/wpsec';
import { getWebsiteByDomain } from '../config/db';

const router = Router();

// Get site information
router.get('/:domain/info', async (req, res) => {
  try {
    const { domain } = req.params;

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Get site info
    const info = await api.getSiteInfo();
    res.json(info);
  } catch (error) {
    console.error('Error getting site info:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get site vulnerabilities
router.get('/:domain/vulnerabilities', async (req, res) => {
  try {
    const { domain } = req.params;

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Get vulnerabilities
    const vulnerabilities = await api.getVulnerabilities();
    res.json(vulnerabilities);
  } catch (error) {
    console.error('Error getting vulnerabilities:', error);
    res.status(500).json({ error: error.message });
  }
});

// Check core integrity
router.get('/:domain/core-check', async (req, res) => {
  try {
    const { domain } = req.params;

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Check core integrity
    const result = await api.checkCoreIntegrity();
    res.json(result);
  } catch (error) {
    console.error('Error checking core integrity:', error);
    res.status(500).json({ error: error.message });
  }
});

export default router;
