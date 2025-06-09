import { Router } from 'express';
import { WPSecAPI } from '../services/wpsec';
import type { SiteInfo, Vulnerability, CoreCheckResult } from '../types/wpsec';
import { getWebsiteByDomain, updateWPCoreLayer } from '../config/db';
import pool from '../config/db';
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
      wpVersion: info.wordpress.version,
      totalPlugins: info.plugins.total_count,
      totalThemes: info.themes.total_count,
      isMultisite: info.wordpress.is_multisite,
      isSSL: info.wordpress.is_ssl,
      phpVersion: info.server.php_version
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
    
    // Debug log the raw response from WPSec API
    console.log('Core check raw response:', JSON.stringify(result, null, 2));

    // Update the wpcore_layer column in the database
    await updateWPCoreLayer(website.id, result);

    logger.info({
      message: 'Core integrity check completed',
      domain,
      status: result.status,
      integrityStatus: result.core_files?.summary?.missing_count > 0 || result.core_files?.summary?.modified_count > 0 ? 'compromised' : 'ok',
      totalModifiedFiles: result.core_files?.summary?.modified_count || 0,
      totalMissingFiles: result.core_files?.summary?.missing_count || 0
    }, {
      component: 'sites-controller',
      event: 'core_check_completed'
    });

    // Prepare simplified response
    const response = {
      status: result.status,
      timestamp: result.timestamp,
      wordpress_version: result.wordpress?.current_version,
      wordpress_update_required: result.wordpress?.update_required,
      integrity_status: result.core_files?.summary?.missing_count > 0 || result.core_files?.summary?.modified_count > 0 ? 'compromised' : 'ok',
      message: result.core_files?.summary?.missing_count > 0 || result.core_files?.summary?.modified_count > 0 ?
        `Found ${result.core_files?.summary?.modified_count || 0} modified files and ${result.core_files?.summary?.missing_count || 0} missing files.` :
        'Core integrity check completed. Integrity verified.',
      modified_files_count: result.core_files?.summary?.modified_count || 0,
      missing_files_count: result.core_files?.summary?.missing_count || 0,
      total_files_checked: result.core_files?.summary?.total_checked || 0,
      permission_issues: result.permissions?.summary?.total_issues || 0
    };
    
    // Debug log the simplified response
    console.log('Core check simplified response:', JSON.stringify(response, null, 2));
    
    // Return the response
    res.json(response);
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

// Transfer website ownership
router.post('/:domain/transfer-ownership', async (req, res) => {
  try {
    const { domain } = req.params;
    const { newOwnerUid } = req.body;

    if (!newOwnerUid) {
      return res.status(400).json({ 
        error: 'Missing required parameter: newOwnerUid is required' 
      });
    }

    logger.debug({
      message: 'Transferring website ownership',
      domain,
      newOwnerUid
    }, {
      component: 'sites-controller',
      event: 'transfer_ownership_request'
    });

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      logger.warn({
        message: 'Website not found',
        domain
      }, {
        component: 'sites-controller',
        event: 'transfer_ownership_not_found'
      });
      return res.status(404).json({ error: 'Website not found' });
    }
    
    // The database schema uses UUID for website.id and uid for the owner
    const websiteId = website.id;
    // TypeScript doesn't know about the uid field in the Website interface from db.ts
    // but we know it exists in the actual database based on the Prisma schema
    const currentOwnerUid = (website as any).uid || (website as any).user_id;

    // Verify the new owner exists
    const userQuery = `SELECT uid FROM users WHERE uid = $1`;
    const userResult = await pool.query(userQuery, [newOwnerUid]);
    
    if (userResult.rows.length === 0) {
      logger.warn({
        message: 'New owner not found',
        newOwnerUid
      }, {
        component: 'sites-controller',
        event: 'transfer_ownership_invalid_user'
      });
      return res.status(404).json({ error: 'New owner not found' });
    }

    // Begin transaction
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Update website ownership
      const updateQuery = `
        UPDATE websites 
        SET uid = $1, updated_at = NOW() 
        WHERE id = $2 AND uid = $3
        RETURNING id, domain, uid
      `;
      const updateResult = await client.query(updateQuery, [newOwnerUid, websiteId, currentOwnerUid]);
      
      if (updateResult.rows.length === 0) {
        throw new Error('Failed to update website ownership');
      }

      const updatedWebsite = updateResult.rows[0];

      // Create a transfer record
      const transferQuery = `
        INSERT INTO website_transfers (website_id, uid, domain, created_at, updated_at)
        VALUES ($1, $2, $3, NOW(), NOW())
        RETURNING id
      `;
      await client.query(transferQuery, [websiteId, newOwnerUid, domain]);

      await client.query('COMMIT');

      logger.info({
        message: 'Website ownership transferred successfully',
        websiteId,
        domain,
        previousOwner: currentOwnerUid,
        newOwner: newOwnerUid
      }, {
        component: 'sites-controller',
        event: 'transfer_ownership_success'
      });

      res.json({ 
        status: 'success', 
        message: 'Website ownership transferred successfully',
        website: {
          id: websiteId,
          domain,
          owner: newOwnerUid
        }
      });

    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }

  } catch (error) {
    logger.error({
      message: 'Error transferring website ownership',
      error: error instanceof Error ? error : new Error(String(error) || 'Unknown error'),
      websiteId: req.body.websiteId
    }, {
      component: 'sites-controller',
      event: 'transfer_ownership_error'
    });
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
  }
});

/**
 * Check the health of the WPSec plugin on the site
 * GET /:domain/health
 * Returns plugin status information including active state and version
 */
router.get('/:domain/health', async (req, res) => {
  try {
    const { domain } = req.params;

    logger.debug({
      message: 'Checking site health',
      domain
    }, {
      component: 'sites-controller',
      event: 'check_site_health'
    });

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Get health status
    logger.debug({
      message: 'Pinging WPSec plugin',
      domain
    }, {
      component: 'sites-controller',
      event: 'ping_wpsec_plugin'
    });

    const result = await api.ping();

    logger.info({
      message: 'Site health check completed',
      domain,
      pluginActive: result.data.plugin_active,
      pluginVersion: result.data.plugin_version
    }, {
      component: 'sites-controller',
      event: 'site_health_check_completed'
    });

    res.json(result);
  } catch (error) {
    const errorDomain = req.params.domain;
    logger.error({
      message: 'Error checking site health',
      error: error instanceof Error ? error : new Error(String(error) || 'Unknown error'),
      domain: errorDomain
    }, {
      component: 'sites-controller',
      event: 'site_health_check_error'
    });
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
  }
});

/**
 * Get activity logs for a site with filtering support
 * GET /:domain/activity-log
 * Supports filtering via query parameters:
 * - start: Start date (YYYY-MM-DD)
 * - end: End date (YYYY-MM-DD)
 * - event_type: Type of event (login_attempt, role_change, etc.)
 * - severity: Severity level (info, warning, critical)
 * - and more filters as documented in the response
 */
router.get('/:domain/activity-log', async (req, res) => {
  try {
    const { domain } = req.params;
    
    logger.debug({
      message: 'Getting activity logs',
      domain,
      filters: req.query
    }, {
      component: 'sites-controller',
      event: 'get_activity_logs'
    });
    
    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }
    
    // Create WPSec API instance
    const api = new WPSecAPI(domain);
    
    // Extract filters from query parameters
    const filters = {
      start: req.query.start as string,
      end: req.query.end as string,
      event_type: req.query.event_type as string,
      severity: req.query.severity as string
    };
    
    // Get activity logs with filters
    const result = await api.getActivityLogs(filters);
    
    // Print the full response for debugging
    console.log('Activity log API response:', JSON.stringify(result, null, 2));
    
    logger.info({
      message: 'Activity logs retrieved',
      domain,
      totalLogs: result.data?.total,
      page: result.data?.page,
      totalPages: result.data?.pages
    }, {
      component: 'sites-controller',
      event: 'activity_logs_retrieved'
    });
    
    res.json(result);
  } catch (error) {
    const errorDomain = req.params.domain;
    logger.error({
      message: 'Error getting activity logs',
      error: error instanceof Error ? error : new Error(String(error) || 'Unknown error'),
      domain: errorDomain,
      filters: req.query
    }, {
      component: 'sites-controller',
      event: 'activity_logs_error'
    });
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
  }
});

/**
 * Get uptime information from the WordPress site
 * GET /:domain/uptime
 * Returns uptime data including status, response time, WP version, and system health metrics
 */
router.get('/:domain/uptime', async (req, res) => {
  try {
    const { domain } = req.params;

    logger.debug({
      message: 'Getting site uptime information',
      domain
    }, {
      component: 'sites-controller',
      event: 'get_site_uptime'
    });

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Get uptime information
    logger.debug({
      message: 'Fetching uptime information from WPSec API',
      domain
    }, {
      component: 'sites-controller',
      event: 'fetch_site_uptime'
    });

    const result = await api.getUptime();

    logger.info({
      message: 'Site uptime information retrieved',
      domain,
      status: result.data.status,
      wpVersion: result.data.wp_version,
      wpsecVersion: result.data.wpsec_version,
      responseTime: result.data.response_time,
      hasFatalErrors: result.data.has_fatal_errors
    }, {
      component: 'sites-controller',
      event: 'site_uptime_retrieved'
    });

    res.json(result);
  } catch (error) {
    const errorDomain = req.params.domain;
    logger.error({
      message: 'Error getting site uptime information',
      error: error instanceof Error ? error : new Error(String(error) || 'Unknown error'),
      domain: errorDomain
    }, {
      component: 'sites-controller',
      event: 'site_uptime_error'
    });
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
  }
});

export default router;
