import { Router } from 'express';
import { WPSecAPI } from '../services/wpsec';
import { getWebsiteByDomain } from '../config/db';
import { logger } from '../services/logger';

const router = Router();

// Add file to whitelist
router.post('/:domain', async (req, res) => {
  try {
    const { domain } = req.params;
    const { file_path, reason, added_by } = req.body;

    logger.debug({
      message: 'Adding file to whitelist',
      domain,
      filePath: file_path,
      reason,
      addedBy: added_by
    }, {
      component: 'whitelist-controller',
      event: 'add_to_whitelist'
    });

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Add file to whitelist
    logger.debug({
      message: 'Sending whitelist request to WPSec API',
      domain,
      filePath: file_path
    }, {
      component: 'whitelist-controller',
      event: 'whitelist_request'
    });

    await api.whitelistFile(file_path, reason, added_by);

    logger.info({
      message: 'File added to whitelist successfully',
      domain,
      filePath: file_path,
      reason,
      addedBy: added_by
    }, {
      component: 'whitelist-controller',
      event: 'file_whitelisted'
    });

    res.json({ success: true });
  } catch (error: any) {
    const errorDomain = req.params.domain;
    logger.error({
      message: 'Error adding file to whitelist',
      error,
      domain: errorDomain,
      filePath: req.body.file_path
    }, {
      component: 'whitelist-controller',
      event: 'whitelist_error'
    });
    res.status(500).json({ error: error.message });
  }
});

// Get whitelisted files
router.get('/:domain/files', async (req, res) => {
  try {
    const { domain } = req.params;
    const { include_details, verify_integrity } = req.query;

    logger.debug({
      message: 'Getting whitelisted files',
      domain,
      includeDetails: include_details === '1',
      verifyIntegrity: verify_integrity === '1'
    }, {
      component: 'whitelist-controller',
      event: 'get_whitelisted_files'
    });

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Get whitelisted files
    logger.debug({
      message: 'Fetching whitelisted files from WPSec API',
      domain
    }, {
      component: 'whitelist-controller',
      event: 'fetch_whitelisted_files'
    });

    const files = await api.getWhitelistedFiles(
      include_details === '1',
      verify_integrity === '1'
    );

    logger.info({
      message: 'Whitelisted files retrieved',
      domain,
      totalFiles: files.length,
      includeDetails: include_details === '1',
      verifyIntegrity: verify_integrity === '1'
    }, {
      component: 'whitelist-controller',
      event: 'files_retrieved'
    });

    res.json(files);
  } catch (error: any) {
    const errorDomain = req.params.domain;
    logger.error({
      message: 'Error getting whitelisted files',
      error,
      domain: errorDomain
    }, {
      component: 'whitelist-controller',
      event: 'get_files_error'
    });
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
