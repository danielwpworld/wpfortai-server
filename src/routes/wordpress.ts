import { Router } from 'express';
import { WPSecAPI } from '../services/wpsec';
import { getWebsiteByDomain } from '../config/db';
import { logger } from '../services/logger';
import { CoreReinstallStore } from '../services/core-reinstall-store';
import redis from '../config/redis';

const router = Router();

// Default payload for core-reinstall
const DEFAULT_CORE_REINSTALL_PAYLOAD = {
  version: 'current',
  backup: true,
  skip_content: true,
  skip_config: true,
  verify_checksums: true,
  restore_index_files: true
};

/**
 * POST /api/wordpress/:domain/core-reinstall
 * Triggers a core reinstall using the default payload.
 */
router.post('/:domain/core-reinstall', async (req, res) => {
  try {
    const { domain } = req.params;
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }
    const api = new WPSecAPI(domain);
    logger.info({
      message: 'Calling core-reinstall',
      domain,
      payload: DEFAULT_CORE_REINSTALL_PAYLOAD
    }, {
      component: 'wordpress-controller',
      event: 'core_reinstall_start'
    });
    const result = await api.coreReinstall(DEFAULT_CORE_REINSTALL_PAYLOAD);
    logger.info({
      message: 'core-reinstall succeeded',
      domain,
      result
    }, {
      component: 'wordpress-controller',
      event: 'core_reinstall_success'
    });

    // Store in Redis (CoreReinstallStore)
    const { operation_id, message, version, started_at, check_status_endpoint } = result;
    const { CoreReinstallStore } = await import('../services/core-reinstall-store');
    await CoreReinstallStore.createCoreReinstall(domain, {
      domain,
      operation_id,
      started_at,
      status: 'in_progress', // Explicitly set status to in_progress
      message: message || 'Core reinstall started',
      version,
      check_status_endpoint
    });

    // Create and broadcast core reinstall started event
    try {
      // Construct event data
      const eventData = {
        origin: 'backend',
        vertical: 'wpcore_layer',
        status: 'success',
        message: 'WordPress core system fix initiated.',
        operation_id,
        version,
        started_at: new Date().toISOString(),
        check_status_endpoint
      };
      
      // Create and broadcast the event
      const eventName = 'wpcore_layer.core_reinstall.started';
      
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
          message: 'Successfully created and broadcast core reinstall started event',
          domain,
          operation_id,
          eventName
        }, {
          component: 'wordpress-controller',
          event: 'core_reinstall_event_created'
        });
      } else {
        logger.warn({
          message: 'Failed to create core reinstall started event',
          domain,
          operation_id,
          status: eventResponse.status
        }, {
          component: 'wordpress-controller',
          event: 'core_reinstall_event_failed'
        });
      }
    } catch (eventError) {
      logger.error({
        message: 'Error creating core reinstall started event',
        error: eventError instanceof Error ? eventError : new Error(String(eventError)),
        domain,
        operation_id
      }, {
        component: 'wordpress-controller',
        event: 'core_reinstall_event_error'
      });
      // Don't fail the endpoint if event creation fails
    }
    
    // Insert record into website_core_reinstalls immediately after success
    try {
      const { createCoreReinstallRecord } = await import('../config/db');
      await createCoreReinstallRecord({
        website_id: website.id, // UUID
        operation_id,
        status: 'in_progress',
        message: 'Core reinstall started',
        version,
        check_status_endpoint,
        started_at
      });
    } catch (dbError) {
      const err = dbError instanceof Error ? dbError : new Error(String(dbError) || 'Unknown error');
      logger.error({
        message: 'Failed to insert website_core_reinstalls record after core-reinstall',
        error: err,
        websiteId: website.id,
        operation_id
      }, {
        component: 'wordpress-controller',
        event: 'core_reinstall_db_insert_error'
      });
      // Optionally: don't fail the endpoint if DB insert fails, just log
    }

    // Core-check and wpcore_layer update will be handled by the core-reinstall-complete webhook
    logger.info({
      message: 'Core reinstall initiated, wpcore_layer will be updated when complete webhook is received',
      domain,
      operation_id
    }, {
      component: 'wordpress-controller',
      event: 'core_reinstall_initiated'
    });
    
    res.json(result);
  } catch (error) {
    const err = error instanceof Error ? error : new Error(String(error) || 'Unknown error');
    logger.error({
      message: 'core-reinstall failed',
      error: err
    }, {
      component: 'wordpress-controller',
      event: 'core_reinstall_error'
    });
    
    // Create and broadcast core reinstall failed event
    try {
      const domain = req.params.domain;
      
      // Construct event data
      const eventData = {
        origin: 'backend',
        vertical: 'wpcore_layer',
        status: 'failed',
        message: 'WordPress core system fix failed.',
        error: err.message,
        failed_at: new Date().toISOString()
      };
      
      // Create and broadcast the event
      const eventName = 'wpcore_layer.core_reinstall.failed';
      
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
          message: 'Successfully created and broadcast core reinstall failed event',
          domain,
          eventName
        }, {
          component: 'wordpress-controller',
          event: 'core_reinstall_failure_event_created'
        });
      } else {
        logger.warn({
          message: 'Failed to create core reinstall failed event',
          domain,
          status: eventResponse.status
        }, {
          component: 'wordpress-controller',
          event: 'core_reinstall_failure_event_failed'
        });
      }
    } catch (eventError) {
      logger.error({
        message: 'Error creating core reinstall failed event',
        error: eventError instanceof Error ? eventError : new Error(String(eventError)),
        domain: req.params.domain
      }, {
        component: 'wordpress-controller',
        event: 'core_reinstall_failure_event_error'
      });
      // Don't let event creation failure affect the response
    }
    
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/wordpress/:domain/core-reinstall-status
 * Returns the status of the most recent core reinstall operation for a domain
 */
router.get('/:domain/core-reinstall-status', async (req, res) => {
  try {
    const { domain } = req.params;
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // First check if there's an active core reinstall in Redis
    const operationId = await redis.get(`active_core_reinstall:${domain}`);
    
    if (operationId) {
      // Get the core reinstall data from Redis
      const reinstallData = await CoreReinstallStore.getCoreReinstall(operationId);
      if (reinstallData) {
        // Convert the Redis data to a response object
        return res.json({
          status: reinstallData.status,
          message: reinstallData.message,
          operation_id: reinstallData.operation_id,
          started_at: reinstallData.started_at,
          completed_at: reinstallData.completed_at || null,
          version: reinstallData.version
        });
      }
    }

    // If no active reinstall found in Redis, check the database for the most recent one
    const pool = (await import('../config/db')).default;
    const result = await pool.query(
      `SELECT operation_id, status, message, started_at, completed_at 
       FROM website_core_reinstalls 
       WHERE website_id = $1 
       ORDER BY started_at DESC LIMIT 1`,
      [website.id] // website.id is a UUID
    );

    if (result.rows.length === 0) {
      return res.json({ status: 'none', message: 'No core reinstall operations found' });
    }

    return res.json(result.rows[0]);
  } catch (error) {
    const err = error instanceof Error ? error : new Error(String(error));
    logger.error({
      message: 'Error getting core reinstall status',
      error: err
    }, {
      component: 'wordpress-controller',
      event: 'core_reinstall_status_error'
    });
    res.status(500).json({ error: err.message });
  }
});

export default router;
