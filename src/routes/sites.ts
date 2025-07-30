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

/**
 * Get historical uptime data for a website
 * GET /:domain/uptime-history
 * Returns the latest 50 uptime entries for time series visualization
 */
router.get('/:domain/uptime-history', async (req, res) => {
  try {
    const { domain } = req.params;
    const limit = parseInt(req.query.limit as string) || 50;

    logger.debug({
      message: 'Getting site uptime history',
      domain,
      limit
    }, {
      component: 'sites-controller',
      event: 'get_site_uptime_history'
    });

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Get the website ID (which should be a UUID based on the memory)
    const websiteId = website.id;

    // Query the latest uptime entries from the database
    const query = `
      SELECT 
        id, 
        created_at, 
        status, 
        response_time_seconds, 
        wp_version, 
        wpsec_version, 
        maintenance_mode, 
        database_connected, 
        memory_usage_percent, 
        memory_critical, 
        filesystem_accessible, 
        has_fatal_errors, 
        plugin_status, 
        timestamp
      FROM website_uptime 
      WHERE website_id = $1 
      ORDER BY created_at DESC 
      LIMIT $2
    `;

    const result = await pool.query(query, [websiteId, limit]);

    // Format the data for frontend time series visualization
    const uptimeHistory = result.rows.map(row => ({
      id: row.id,
      timestamp: row.timestamp,
      date: row.created_at,
      status: row.status,
      responseTime: parseFloat(row.response_time_seconds),
      wpVersion: row.wp_version,
      wpsecVersion: row.wpsec_version,
      maintenanceMode: row.maintenance_mode,
      database: {
        connected: row.database_connected,
        error: row.database_error
      },
      memory: {
        usagePercent: parseFloat(row.memory_usage_percent),
        critical: row.memory_critical
      },
      filesystem: {
        accessible: row.filesystem_accessible
      },
      hasFatalErrors: row.has_fatal_errors,
      pluginStatus: row.plugin_status
    }));

    logger.info({
      message: 'Site uptime history retrieved',
      domain,
      entriesCount: uptimeHistory.length
    }, {
      component: 'sites-controller',
      event: 'site_uptime_history_retrieved'
    });

    res.json({
      success: true,
      data: {
        domain,
        count: uptimeHistory.length,
        history: uptimeHistory
      }
    });
  } catch (error) {
    const errorDomain = req.params.domain;
    logger.error({
      message: 'Error getting site uptime history',
      error: error instanceof Error ? error : new Error(String(error) || 'Unknown error'),
      domain: errorDomain
    }, {
      component: 'sites-controller',
      event: 'site_uptime_history_error'
    });
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
  }
});

/**
 * Get website connectivity status
 * Checks uptime, ping, initial plugin installation, and layer data freshness
 */
router.get('/:domain/connectivity', async (req, res) => {
  try {
    const { domain } = req.params;

    logger.debug({
      message: 'Checking website connectivity',
      domain
    }, {
      component: 'sites-controller',
      event: 'check_connectivity'
    });

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    const websiteId = website.id;
    const now = new Date();
    const tenMinutesAgo = new Date(now.getTime() - 10 * 60 * 1000);
    const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    const twoDaysAgo = new Date(now.getTime() - 2 * 24 * 60 * 60 * 1000);

    // 1. Check uptime (last probe within 10 minutes)
    const uptimeQuery = `
      SELECT status, created_at, plugin_status, database_connected, filesystem_accessible
      FROM website_uptime 
      WHERE website_id = $1 
      ORDER BY created_at DESC 
      LIMIT 1
    `;
    const uptimeResult = await pool.query(uptimeQuery, [websiteId]);
    
    let uptime = {
      connected: false,
      last_check: null as string | null,
      status: null as string | null
    };

    if (uptimeResult.rows.length > 0) {
      const lastUptime = uptimeResult.rows[0];
      const lastCheck = new Date(lastUptime.created_at);
      uptime = {
        connected: lastCheck > tenMinutesAgo && lastUptime.status === 'up',
        last_check: lastUptime.created_at,
        status: lastUptime.status
      };
    }

    // 2. Ping check
    let ping = {
      connected: false,
      plugin_active: false,
      plugin_version: null as string | null,
      error: null as string | null
    };

    try {
      const api = new WPSecAPI(domain);
      const pingResult = await api.ping();
      ping = {
        connected: true,
        plugin_active: pingResult.data.plugin_active || false,
        plugin_version: pingResult.data.plugin_version || null,
        error: null
      };
    } catch (error) {
      const err = error instanceof Error ? error : new Error('Unknown error');
      ping.error = err.message;
    }

    // 3. Check initial plugin installation
    const initial_install = {
      installed: website.initial_plugin_installed || false
    };

    // 4. Check layers data freshness
    const layers = [];

    // Check website_data for non-filesystem layers (within 1 day)
    const layersQuery = `
      SELECT wpcore_layer, application_layer, network_layer, fetched_at
      FROM website_data 
      WHERE website_id = $1 
      ORDER BY fetched_at DESC 
      LIMIT 1
    `;
    const layersResult = await pool.query(layersQuery, [websiteId]);

    if (layersResult.rows.length > 0) {
      const layerData = layersResult.rows[0];
      const fetchedAt = new Date(layerData.fetched_at);
      const isRecent = fetchedAt > oneDayAgo;

      // WP Core Layer
      if (layerData.wpcore_layer) {
        layers.push({
          name: 'wpcore_layer',
          fresh: isRecent,
          last_updated: layerData.fetched_at,
          data_available: true
        });
      } else {
        layers.push({
          name: 'wpcore_layer',
          fresh: false,
          last_updated: null,
          data_available: false
        });
      }

      // Application Layer
      if (layerData.application_layer) {
        layers.push({
          name: 'application_layer',
          fresh: isRecent,
          last_updated: layerData.fetched_at,
          data_available: true
        });
      } else {
        layers.push({
          name: 'application_layer',
          fresh: false,
          last_updated: null,
          data_available: false
        });
      }

      // Network Layer
      if (layerData.network_layer) {
        layers.push({
          name: 'network_layer',
          fresh: isRecent,
          last_updated: layerData.fetched_at,
          data_available: true
        });
      } else {
        layers.push({
          name: 'network_layer',
          fresh: false,
          last_updated: null,
          data_available: false
        });
      }
    } else {
      // No data available for any layer
      ['wpcore_layer', 'application_layer', 'network_layer'].forEach(layerName => {
        layers.push({
          name: layerName,
          fresh: false,
          last_updated: null,
          data_available: false
        });
      });
    }

    // Check filesystem layer from website_scans (within 2 days)
    const filesystemQuery = `
      SELECT completed_at, status
      FROM website_scans 
      WHERE website_id = $1 AND status = 'completed'
      ORDER BY completed_at DESC 
      LIMIT 1
    `;
    const filesystemResult = await pool.query(filesystemQuery, [websiteId]);

    if (filesystemResult.rows.length > 0) {
      const lastScan = filesystemResult.rows[0];
      const completedAt = new Date(lastScan.completed_at);
      const isRecent = completedAt > twoDaysAgo;

      layers.push({
        name: 'filesystem_layer',
        fresh: isRecent,
        last_updated: lastScan.completed_at,
        data_available: true
      });
    } else {
      layers.push({
        name: 'filesystem_layer',
        fresh: false,
        last_updated: null,
        data_available: false
      });
    }

    const response = {
      uptime,
      ping,
      initial_install,
      layers
    };

    logger.info({
      message: 'Website connectivity check completed',
      domain,
      uptime: uptime.connected,
      ping: ping.connected,
      initial_install: initial_install.installed,
      layers_fresh: layers.filter(l => l.fresh).length
    }, {
      component: 'sites-controller',
      event: 'connectivity_check_completed'
    });

    res.json(response);
  } catch (error) {
    const err = error instanceof Error ? error : new Error('Unknown error');
    logger.error({
      message: 'Failed to check website connectivity',
      error: err,
      path: req.path
    }, {
      component: 'sites-controller',
      event: 'connectivity_check_error'
    });
    res.status(500).json({ error: err.message });
  }
});

export default router;
