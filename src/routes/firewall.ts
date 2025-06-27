import { Router } from 'express';
import { WPSecAPI } from '../services/wpsec';
import type { FirewallStatus, FirewallLog } from '../types/wpsec';
import { getWebsiteByDomain } from '../config/db';
import { logger } from '../services/logger';
import fetch from 'node-fetch';

const router = Router();

// Get firewall status
router.get('/:domain/status', async (req, res) => {
  try {
    const { domain } = req.params;

    logger.debug({
      message: 'Getting firewall status',
      domain
    }, {
      component: 'firewall-controller',
      event: 'get_firewall_status'
    });

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Get firewall status
    logger.debug({
      message: 'Fetching firewall status from WPSec API',
      domain
    }, {
      component: 'firewall-controller',
      event: 'fetch_firewall_status'
    });

    const status = await api.getFirewallStatus();

    logger.info({
      message: 'Firewall status retrieved',
      domain,
      isActive: status.active,
      totalRules: (status as any).rules?.length || 0
    }, {
      component: 'firewall-controller',
      event: 'firewall_status_retrieved'
    });

    res.json(status);
  } catch (error: any) {
    const errorDomain = req.params.domain;
    logger.error({
      message: 'Error getting firewall status',
      error,
      domain: errorDomain
    }, {
      component: 'firewall-controller',
      event: 'firewall_status_error'
    });
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
  }
});

// Toggle firewall
router.post('/:domain/toggle', async (req, res) => {
  try {
    const { domain } = req.params;
    const { active } = req.body;

    logger.debug({
      message: 'Toggling firewall status',
      domain,
      targetState: active
    }, {
      component: 'firewall-controller',
      event: 'toggle_firewall'
    });

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
    logger.debug({
      message: 'Sending toggle request to WPSec API',
      domain,
      targetState: active
    }, {
      component: 'firewall-controller',
      event: 'toggle_firewall_request'
    });

    await api.toggleFirewall(active);
    
    // Create and broadcast firewall toggle event
    try {
      // Determine event name based on toggle state
      const eventName = active ? 'firewall_layer.toggled.on' : 'firewall_layer.toggled.off';
      
      // Construct event data
      const eventData = {
        origin: 'backend',
        vertical: 'network_layer',
        status: 'success',
        message: active ? 'Multi-functional firewall activated' : 'Multi-functional firewall deactivated',
        toggled_at: new Date().toISOString()
      };
      
      // First store event in database, then broadcast
      const eventResponse = await fetch(`http://localhost:${process.env.PORT || 3001}/api/events/create`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-wpfort-token': process.env.INTERNAL_API_TOKEN || '123123123'
        },
        body: JSON.stringify({
          domain,
          event: eventName,
          data: eventData
        })
      });
      
      if (eventResponse.ok) {
        logger.info({
          message: `Successfully created and broadcast firewall toggled ${active ? 'on' : 'off'} event`,
          domain,
          eventName
        }, {
          component: 'firewall-controller',
          event: 'firewall_toggle_event_created'
        });
      } else {
        logger.warn({
          message: `Failed to create firewall toggled ${active ? 'on' : 'off'} event`,
          domain,
          status: eventResponse.status
        }, {
          component: 'firewall-controller',
          event: 'firewall_toggle_event_failed'
        });
      }
    } catch (eventError) {
      logger.error({
        message: 'Error creating firewall toggle event',
        error: eventError instanceof Error ? eventError : new Error(String(eventError)),
        domain
      }, {
        component: 'firewall-controller',
        event: 'firewall_toggle_event_error'
      });
      // Don't fail the endpoint if event creation fails
    }
    
    // Update the network_status.active field in the database
    try {
      const { updateFirewallStatus } = await import('../config/db');
      await updateFirewallStatus(String(website.id), active);
      
      logger.info({
        message: 'Updated network_status.active in database',
        domain,
        websiteId: website.id,
        active
      }, {
        component: 'firewall-controller',
        event: 'firewall_status_db_updated'
      });
    } catch (dbError) {
      logger.warn({
        message: 'Failed to update network_status.active in database, but firewall was toggled',
        domain,
        active,
        error: dbError
      }, {
        component: 'firewall-controller',
        event: 'firewall_status_db_update_failed'
      });
      // Continue since the primary operation succeeded
    }
    
    // Fetch firewall logs and update the network_layer column
    try {
      // Use 7 days period for firewall logs as specified
      const firewallLogs = await api.getFirewallLogs(7);
      
      const { updateNetworkLayer } = await import('../config/db');
      await updateNetworkLayer(String(website.id), firewallLogs);
      
      logger.info({
        message: 'Updated network_layer with firewall logs',
        domain,
        websiteId: website.id,
        logsCount: firewallLogs.length || 0
      }, {
        component: 'firewall-controller',
        event: 'network_layer_updated'
      });
    } catch (logsError) {
      logger.warn({
        message: 'Failed to update network_layer with firewall logs, but firewall was toggled',
        domain,
        error: logsError
      }, {
        component: 'firewall-controller',
        event: 'network_layer_update_failed'
      });
      // Continue since the primary operation succeeded
    }

    logger.info({
      message: 'Firewall status toggled successfully',
      domain,
      newState: active
    }, {
      component: 'firewall-controller',
      event: 'firewall_toggled'
    });

    res.json({ success: true });
  } catch (error) {
    console.error('Error toggling firewall:', error);
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
  }
});

// Get firewall logs
router.get('/:domain/logs', async (req, res) => {
  try {
    const { domain } = req.params;
    const { period } = req.query;

    logger.debug({
      message: 'Getting firewall logs',
      domain,
      period
    }, {
      component: 'firewall-controller',
      event: 'get_firewall_logs'
    });

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Get firewall logs
    logger.debug({
      message: 'Fetching firewall logs from WPSec API',
      domain,
      period
    }, {
      component: 'firewall-controller',
      event: 'fetch_firewall_logs'
    });

    const logs = await api.getFirewallLogs(period ? parseInt(period as string) : undefined);

    logger.info({
      message: 'Firewall logs retrieved',
      domain,
      period,
      totalLogs: logs.length || 0
    }, {
      component: 'firewall-controller',
      event: 'firewall_logs_retrieved'
    });

    res.json(logs);
  } catch (error) {
    console.error('Error getting firewall logs:', error);
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
  }
});

// Whitelist IP
router.post('/:domain/whitelist', async (req, res) => {
  try {
    const { domain } = req.params;
    const { ip, action } = req.body;

    logger.debug({
      message: 'Managing firewall whitelist',
      domain,
      ip,
      action
    }, {
      component: 'firewall-controller',
      event: 'manage_whitelist'
    });

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
    logger.debug({
      message: 'Sending whitelist request to WPSec API',
      domain,
      ip,
      action
    }, {
      component: 'firewall-controller',
      event: 'whitelist_request'
    });

    await api.whitelistFirewallIP(ip, action);

    // Create and broadcast whitelist update event
    try {
      // Construct event data
      const eventData = {
        origin: 'backend',
        vertical: 'network_layer',
        status: 'success',
        message: `Firewall rules: ${ip} ${action === 'add' ? 'added to' : 'removed from'} whitelist.`,
        updated_at: new Date().toISOString(),
        ip,
        action
      };
      
      // First store event in database, then broadcast
      const eventResponse = await fetch(`http://localhost:${process.env.PORT || 3001}/api/events/create`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-wpfort-token': process.env.INTERNAL_API_TOKEN || '123123123'
        },
        body: JSON.stringify({
          domain,
          event: 'firewall_layer.whitelist.updated',
          data: eventData
        })
      });
      
      if (eventResponse.ok) {
        logger.info({
          message: 'Successfully created and broadcast whitelist update event',
          domain,
          ip,
          action
        }, {
          component: 'firewall-controller',
          event: 'whitelist_update_event_created'
        });
      } else {
        logger.warn({
          message: 'Failed to create whitelist update event',
          domain,
          ip,
          action,
          status: eventResponse.status
        }, {
          component: 'firewall-controller',
          event: 'whitelist_update_event_failed'
        });
      }
    } catch (eventError) {
      logger.error({
        message: 'Error creating whitelist update event',
        error: eventError instanceof Error ? eventError : new Error(String(eventError)),
        domain,
        ip,
        action
      }, {
        component: 'firewall-controller',
        event: 'whitelist_update_event_error'
      });
      // Don't fail the endpoint if event creation fails
    }

    // Update the network_status field in website_data
    try {
      const { updateNetworkStatus } = await import('../config/db');
      await updateNetworkStatus(String(website.id), ip, 'whitelist', action);
    } catch (updateError) {
      logger.warn({
        message: 'Failed to update network_status, but whitelist was updated',
        domain,
        ip,
        action,
        error: updateError
      }, {
        component: 'firewall-controller',
        event: 'whitelist_network_status_update_failed'
      });
      // Continue since the primary operation succeeded
    }

    logger.info({
      message: `IP ${action === 'add' ? 'added to' : 'removed from'} whitelist`,
      domain,
      ip,
      action
    }, {
      component: 'firewall-controller',
      event: 'whitelist_updated'
    });

    res.json({ success: true });
  } catch (error: any) {
    const errorDomain = req.params.domain;
    logger.error({
      message: 'Error managing firewall whitelist',
      error,
      domain: errorDomain,
      ip: req.body.ip,
      action: req.body.action
    }, {
      component: 'firewall-controller',
      event: 'whitelist_error'
    });
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
  }
});

/**
 * Manage firewall blocklist
 * POST /:domain/blocklist
 * Body: { action: 'block' | 'unblock', ip: string }
 */
router.post('/:domain/blocklist', async (req, res) => {
  try {
    const { domain } = req.params;
    const { ip, action } = req.body;

    if (!ip || !action || !['block', 'unblock'].includes(action)) {
      return res.status(400).json({ 
        error: 'Invalid request. Required parameters: ip and action (block or unblock)' 
      });
    }

    logger.debug({
      message: 'Managing firewall blocklist',
      domain,
      ip,
      action
    }, {
      component: 'firewall-controller',
      event: 'blocklist_request'
    });

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Block/unblock IP
    logger.debug({
      message: 'Sending blocklist request to WPSec API',
      domain,
      ip,
      action
    }, {
      component: 'firewall-controller',
      event: 'blocklist_request'
    });

    await api.blocklistFirewallIP(ip, action);

    // Create and broadcast blocklist update event
    try {
      // Construct event data
      const eventData = {
        origin: 'backend',
        vertical: 'network_layer',
        status: 'success',
        message: `Firewall rules: ${ip} ${action === 'block' ? 'added to' : 'removed from'} blacklist.`,
        updated_at: new Date().toISOString(),
        ip,
        action
      };
      
      // First store event in database, then broadcast
      const eventResponse = await fetch(`http://localhost:${process.env.PORT || 3001}/api/events/create`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-wpfort-token': process.env.INTERNAL_API_TOKEN || '123123123'
        },
        body: JSON.stringify({
          domain,
          event: 'firewall_layer.blacklist.updated',
          data: eventData
        })
      });
      
      if (eventResponse.ok) {
        logger.info({
          message: 'Successfully created and broadcast blacklist update event',
          domain,
          ip,
          action
        }, {
          component: 'firewall-controller',
          event: 'blacklist_update_event_created'
        });
      } else {
        logger.warn({
          message: 'Failed to create blacklist update event',
          domain,
          ip,
          action,
          status: eventResponse.status
        }, {
          component: 'firewall-controller',
          event: 'blacklist_update_event_failed'
        });
      }
    } catch (eventError) {
      logger.error({
        message: 'Error creating blacklist update event',
        error: eventError instanceof Error ? eventError : new Error(String(eventError)),
        domain,
        ip,
        action
      }, {
        component: 'firewall-controller',
        event: 'blacklist_update_event_error'
      });
      // Don't fail the endpoint if event creation fails
    }

    // Update the network_status field in website_data
    try {
      const { updateNetworkStatus } = await import('../config/db');
      await updateNetworkStatus(String(website.id), ip, 'blocklist', action);
    } catch (updateError) {
      logger.warn({
        message: 'Failed to update network_status, but blocklist was updated',
        domain,
        ip,
        action,
        error: updateError
      }, {
        component: 'firewall-controller',
        event: 'blocklist_network_status_update_failed'
      });
      // Continue since the primary operation succeeded
    }

    logger.info({
      message: `IP ${action === 'block' ? 'blocked' : 'unblocked'} successfully`,
      domain,
      ip,
      action
    }, {
      component: 'firewall-controller',
      event: 'blocklist_updated'
    });

    res.json({ success: true });
  } catch (error: any) {
    const errorDomain = req.params.domain;
    logger.error({
      message: 'Error managing firewall blocklist',
      error,
      domain: errorDomain,
      ip: req.body.ip,
      action: req.body.action
    }, {
      component: 'firewall-controller',
      event: 'blocklist_error'
    });
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
  }
});

export default router;
