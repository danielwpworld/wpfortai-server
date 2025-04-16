import { Router } from 'express';
import { WPSecAPI } from '../services/wpsec';
import type { SiteInfo, Vulnerability, CoreIntegrityResult } from '../types/wpsec';
import { getWebsiteByDomain } from '../config/db';
import { logger } from '../services/logger';

const router = Router();

// Get site information
router.get('/:domain/info', async (req, res) => {
  try {
    const { domain } = req.params;

    logger.debug({
      message: 'Getting site information',
      domain
    }, {
      component: 'sites-controller',
      event: 'get_site_info'
    });

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Get site info
    logger.debug({
      message: 'Fetching site info from WPSec API',
      domain
    }, {
      component: 'sites-controller',
      event: 'fetch_site_info'
    });

    const info = await api.getSiteInfo();

    logger.info({
      message: 'Site information retrieved',
      domain,
      wpVersion: (info as any).wp_version,
      totalPlugins: (info as any).plugins?.length || 0,
      totalThemes: (info as any).themes?.length || 0
    }, {
      component: 'sites-controller',
      event: 'site_info_retrieved'
    });

    res.json(info);
  } catch (error: any) {
    const errorDomain = req.params.domain;
    logger.error({
      message: 'Error getting site info',
      error,
      domain: errorDomain
    }, {
      component: 'sites-controller',
      event: 'site_info_error'
    });
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
  }
});

// Get site vulnerabilities
router.get('/:domain/vulnerabilities', async (req, res) => {
  try {
    const { domain } = req.params;

    logger.debug({
      message: 'Getting site vulnerabilities',
      domain
    }, {
      component: 'sites-controller',
      event: 'get_vulnerabilities'
    });

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Get vulnerabilities
    logger.debug({
      message: 'Fetching vulnerabilities from WPSec API',
      domain
    }, {
      component: 'sites-controller',
      event: 'fetch_vulnerabilities'
    });

    const vulnerabilities = await api.getVulnerabilities();

    logger.info({
      message: 'Vulnerabilities retrieved',
      domain,
      totalVulnerabilities: (vulnerabilities as any).length || 0,
      severity: {
        high: (vulnerabilities as any).filter((v: any) => v.severity === 'high').length || 0,
        medium: (vulnerabilities as any).filter((v: any) => v.severity === 'medium').length || 0,
        low: (vulnerabilities as any).filter((v: any) => v.severity === 'low').length || 0
      }
    }, {
      component: 'sites-controller',
      event: 'vulnerabilities_retrieved'
    });

    res.json(vulnerabilities);
  } catch (error) {
    console.error('Error getting vulnerabilities:', error);
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
  }
});

// Check core integrity
router.get('/:domain/core-check', async (req, res) => {
  try {
    const { domain } = req.params;

    logger.debug({
      message: 'Starting core integrity check',
      domain
    }, {
      component: 'sites-controller',
      event: 'start_core_check'
    });

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Check core integrity
    logger.debug({
      message: 'Running core integrity check via WPSec API',
      domain
    }, {
      component: 'sites-controller',
      event: 'run_core_check'
    });

    const result = await api.checkCoreIntegrity();

    logger.info({
      message: 'Core integrity check completed',
      domain,
      status: result.status,
      totalModifiedFiles: (result as any).modified_files?.length || 0,
      totalMissingFiles: (result as any).missing_files?.length || 0
    }, {
      component: 'sites-controller',
      event: 'core_check_completed'
    });

    res.json(result);
  } catch (error: any) {
    const errorDomain = req.params.domain;
    logger.error({
      message: 'Error checking core integrity',
      error,
      domain: errorDomain
    }, {
      component: 'sites-controller',
      event: 'core_check_error'
    });
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
  }
});

export default router;
