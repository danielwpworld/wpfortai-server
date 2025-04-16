import { Router } from 'express';
import { WPSecAPI } from '../services/wpsec';
import { getWebsiteByDomain } from '../config/db';

const router = Router();

// Get firewall status
router.get('/:domain/status', async (req, res) => {
  try {
    const { domain } = req.params;

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Get firewall status
    const status = await api.getFirewallStatus();
    res.json(status);
  } catch (error) {
    console.error('Error getting firewall status:', error);
    res.status(500).json({ error: error.message });
  }
});

// Toggle firewall
router.post('/:domain/toggle', async (req, res) => {
  try {
    const { domain } = req.params;
    const { active } = req.body;

    if (typeof active !== 'boolean') {
      return res.status(400).json({ error: 'active parameter must be a boolean' });
    }

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Toggle firewall
    await api.toggleFirewall(active);
    res.json({ success: true });
  } catch (error) {
    console.error('Error toggling firewall:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get firewall logs
router.get('/:domain/logs', async (req, res) => {
  try {
    const { domain } = req.params;
    const { period } = req.query;

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Get firewall logs
    const logs = await api.getFirewallLogs(period ? parseInt(period as string) : undefined);
    res.json(logs);
  } catch (error) {
    console.error('Error getting firewall logs:', error);
    res.status(500).json({ error: error.message });
  }
});

// Whitelist IP
router.post('/:domain/whitelist', async (req, res) => {
  try {
    const { domain } = req.params;
    const { ip, action } = req.body;

    if (!ip || !action || !['add', 'remove'].includes(action)) {
      return res.status(400).json({ error: 'ip and action (add/remove) are required' });
    }

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Whitelist IP
    await api.whitelistFirewallIP(ip, action);
    res.json({ success: true });
  } catch (error) {
    console.error('Error managing firewall whitelist:', error);
    res.status(500).json({ error: error.message });
  }
});

export default router;
