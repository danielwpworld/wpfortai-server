import { Router } from 'express';
import { WPSecAPI } from '../services/wpsec';
import { getWebsiteByDomain } from '../config/db';
import { logger } from '../services/logger';
import { UpdateStore } from '../services/update-store';
import fetch from 'node-fetch';

const router = Router();

// POST /api/update/:domain/all
router.post('/:domain/all', async (req, res) => {
  try {
    const { domain } = req.params;
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }
    
    // Create a record in Redis for this update operation
    const updateId = await UpdateStore.createUpdate(domain, website.id);
    
    const api = new WPSecAPI(domain);
    logger.info({ 
      message: 'Calling updateAll', 
      domain, 
      updateId, 
      websiteId: website.id 
    }, { 
      component: 'update-controller', 
      event: 'update_all_start' 
    });
    
    // Update Redis status to in-progress
    await UpdateStore.updateStatus(updateId, 'in-progress');
    
    // Create and broadcast plugin update started event
    try {
      // Construct event data
      const eventData = {
        origin: 'backend',
        vertical: 'application_layer',
        status: 'success',
        message: 'Performing update of all vulnerable plugins & Themes.',
        update_id: updateId,
        started_at: new Date().toISOString()
      };
      
      // Create and broadcast the event
      const eventName = 'application_layer.plugins.update.started';
      
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
          message: 'Successfully created and broadcast plugins update started event',
          domain,
          updateId,
          eventName
        }, {
          component: 'update-controller',
          event: 'plugins_update_started_event_created'
        });
      } else {
        logger.warn({
          message: 'Failed to create plugins update started event',
          domain,
          updateId,
          status: eventResponse.status
        }, {
          component: 'update-controller',
          event: 'plugins_update_started_event_failed'
        });
      }
    } catch (eventError) {
      logger.error({
        message: 'Error creating plugins update started event',
        error: eventError instanceof Error ? eventError : new Error(String(eventError)),
        domain,
        updateId
      }, {
        component: 'update-controller',
        event: 'plugins_update_started_event_error'
      });
      // Don't fail the endpoint if event creation fails
    }
    
    // Pass update_id to the WPSecAPI so it can track the update
    await api.updateAll(updateId);
    logger.info({ 
      message: 'updateAll succeeded', 
      domain, 
      updateId, 
      websiteId: website.id 
    }, { 
      component: 'update-controller', 
      event: 'update_all_success' 
    });
    
    // Update Redis status to completed
    await UpdateStore.updateStatus(updateId, 'completed');

    // Run vulnerabilities check and update application_layer in website_data
    try {
      const applicationLayer = await api.getVulnerabilities();
      if (applicationLayer) {
        const pool = (await import('../config/db')).default;
        await pool.query(
          `UPDATE website_data SET application_layer = $1, fetched_at = NOW() WHERE website_id = $2`,
          [applicationLayer, website.id]
        );
        logger.info({
          message: 'application_layer updated after updateAll',
          domain,
          websiteId: website.id,
          updateId
        }, {
          component: 'update-controller',
          event: 'application_layer_updated_after_update_all'
        });
      }
    } catch (appErr) {
      logger.error({
        message: 'Failed to update application_layer after updateAll',
        error: appErr instanceof Error ? appErr : new Error(String(appErr) || 'Unknown error'),
        domain,
        websiteId: website.id
      }, {
        component: 'update-controller',
        event: 'application_layer_update_failed_after_update_all'
      });
      // Do not fail the main response if this step fails
    }

    res.json({ status: 'success' });
  } catch (error) {
    const err = error instanceof Error ? error : new Error(String(error));
    const { domain } = req.params; // Get domain from request params
    
    // Try to get the update ID from the request context if it exists
    const updateId = req.body.updateId;
    if (updateId) {
      // Update Redis status to failed
      try {
        await UpdateStore.updateStatus(updateId, 'failed');
        logger.info({
          message: 'Update status set to failed in Redis',
          updateId,
          domain: domain
        }, {
          component: 'update-controller',
          event: 'update_status_failed'
        });
      } catch (redisErr) {
        const redisError = redisErr instanceof Error ? redisErr : new Error(String(redisErr));
        logger.error({
          message: 'Failed to update Redis status',
          error: redisError,
          updateId,
          domain: domain
        }, {
          component: 'update-controller',
          event: 'update_status_error'
        });
      }
    }
    
    logger.error({ 
      message: 'updateAll failed', 
      error: err,
      domain: domain,
      updateId: updateId
    }, { 
      component: 'update-controller', 
      event: 'update_all_error' 
    });
    res.status(500).json({ error: err.message });
  }
});

// POST /api/update/:domain/items
router.post('/:domain/items', async (req, res) => {
  try {
    const { domain } = req.params;
    const { type, items } = req.body;
    if (!type || !items) {
      return res.status(400).json({ error: 'Missing type or items in request body' });
    }
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }
    // Accepts items as array of objects with slug property, or array of strings
    const itemSlugs = items.map((i: any) => typeof i === 'string' ? i : i.slug).filter(Boolean);
    if (!itemSlugs.length) {
      return res.status(400).json({ error: 'No valid item slugs provided' });
    }
    
    const api = new WPSecAPI(domain);
    logger.info({ 
      message: 'Calling updateItems', 
      domain, 
      type, 
      itemSlugs,
      websiteId: website.id 
    }, { 
      component: 'update-controller', 
      event: 'update_items_start' 
    });
    
    // Create and broadcast plugin update started event
    try {
      // Construct event data
      const eventData = {
        origin: 'backend',
        vertical: 'application_layer',
        status: 'success',
        message: 'Plugin or theme update started.',
        started_at: new Date().toISOString(),
        items: {
          type, // 'plugins' or 'themes'
          slugs: itemSlugs
        },
        count: itemSlugs.length
      };
      
      // Create and broadcast the event
      const eventName = 'application_layer.plugins.update.started';
      
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
          message: 'Successfully created and broadcast plugins update started event',
          domain,
          type,
          itemCount: itemSlugs.length,
          eventName
        }, {
          component: 'update-controller',
          event: 'plugins_update_started_event_created'
        });
      } else {
        logger.warn({
          message: 'Failed to create plugins update started event',
          domain,
          type,
          status: eventResponse.status
        }, {
          component: 'update-controller',
          event: 'plugins_update_started_event_failed'
        });
      }
    } catch (eventError) {
      logger.error({
        message: 'Error creating plugins update started event',
        error: eventError instanceof Error ? eventError : new Error(String(eventError)),
        domain,
        type
      }, {
        component: 'update-controller',
        event: 'plugins_update_started_event_error'
      });
      // Don't fail the endpoint if event creation fails
    }
    
    // Call the WPSecAPI without tracking in Redis
    const updateResult = await api.updateItems(type, itemSlugs);
    logger.info({ 
      message: 'updateItems succeeded', 
      domain, 
      type, 
      itemSlugs, 
      updateResult,
      websiteId: website.id 
    }, { 
      component: 'update-controller', 
      event: 'update_items_success' 
    });

    // Check for errors in updateResult
    if (updateResult && Array.isArray(updateResult.results)) {
      const failed = updateResult.results.filter((r: any) => r.success === false);
      if (failed.length > 0) {
        logger.error({ message: 'Some items failed to update', domain, type, itemSlugs, failed }, { component: 'update-controller', event: 'update_items_partial_failure' });
        return res.status(400).json({
          error: 'Some items failed to update',
          failed,
          updateResult
        });
      }
    }

    // Run vulnerabilities check and update application_layer in website_data
    try {
      const applicationLayer = await api.getVulnerabilities();
      if (applicationLayer) {
        const pool = (await import('../config/db')).default;
        await pool.query(
          `UPDATE website_data SET application_layer = $1, fetched_at = NOW() WHERE website_id = $2`,
          [applicationLayer, website.id]
        );
        logger.info({
          message: 'application_layer updated after updateItems',
          domain,
          websiteId: website.id
        }, {
          component: 'update-controller',
          event: 'application_layer_updated_after_update_items'
        });
      }
    } catch (appErr) {
      logger.error({
        message: 'Failed to update application_layer after updateItems',
        error: appErr instanceof Error ? appErr : new Error(String(appErr) || 'Unknown error'),
        domain,
        websiteId: website.id
      }, {
        component: 'update-controller',
        event: 'application_layer_update_failed_after_update_items'
      });
      // Do not fail the main response if this step fails
    }

    res.json({ status: 'success' });
  } catch (error) {
    const err = error instanceof Error ? error : new Error(String(error));
    const { domain } = req.params;
    
    logger.error({ 
      message: 'updateItems failed', 
      error: err,
      domain: domain
    }, { 
      component: 'update-controller', 
      event: 'update_items_error' 
    });
    res.status(500).json({ error: err.message });
  }
});

// GET /api/update/:domain/status
router.get('/:domain/status', async (req, res) => {
  try {
    const { domain } = req.params;
    
    // Check if the website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }
    
    // Get update data from Redis using the domain-based key
    let updateData = await UpdateStore.getUpdate(domain);
    
    // If no data found with domain key, try to find updates with update_id keys that match this domain
    if (!updateData) {
      // First get all update keys
      const redis = (await import('../config/redis')).default;
      const updateKeys = await redis.keys('update:upd_*');
      
      // Check each key to see if it contains data for this domain
      for (const key of updateKeys) {
        const data = await redis.get(key);
        if (data) {
          try {
            const parsedData = JSON.parse(data);
            if (parsedData.domain === domain) {
              // Found an update for this domain
              if (!updateData) {
                // First match found
                updateData = parsedData;
              } else {
                // Use the most recent update if there are multiple
                if (!updateData.completed_at || 
                    (parsedData.started_at > updateData.started_at && !parsedData.completed_at)) {
                  updateData = parsedData;
                }
              }
            }
          } catch (e) {
            // Ignore parsing errors
            console.error('Error parsing Redis data:', e);
          }
        }
      }
    }
    
    if (!updateData) {
      // No update in progress
      return res.json({
        status: 'none',
        message: 'No update in progress for this domain'
      });
    }
    
    // Return the update status
    return res.json({
      status: updateData.status,
      started_at: updateData.started_at,
      completed_at: updateData.completed_at,
      items: updateData.items,
      domain: updateData.domain,
      website_id: updateData.website_id
    });
  } catch (error) {
    const err = error instanceof Error ? error : new Error(String(error));
    logger.error({
      message: 'Failed to get update status',
      error: err,
      path: req.path
    }, {
      component: 'update-controller',
      event: 'update_status_error'
    });
    res.status(500).json({ error: err.message });
  }
});

export default router;
