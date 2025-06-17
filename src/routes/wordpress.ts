import { Router } from 'express';
import { WPSecAPI } from '../services/wpsec';
import { getWebsiteByDomain } from '../config/db';
import { logger } from '../services/logger';

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
    const { operation_id, status, message, version, started_at, check_status_endpoint } = result;
    const { CoreReinstallStore } = await import('../services/core-reinstall-store');
    await CoreReinstallStore.createCoreReinstall(domain, {
      domain,
      operation_id,
      started_at,
      status,
      message,
      version,
      check_status_endpoint
    });

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

    // Schedule a delayed core-check to update the database after core reinstall completes
    setTimeout(async () => {
      try {
        logger.info({
          message: 'Running delayed core-check after core-reinstall',
          domain,
          operation_id,
          websiteId: website.id
        }, {
          component: 'wordpress-controller',
          event: 'delayed_core_check_start'
        });
        
        const coreCheckResult = await api.checkCoreIntegrity();
        
        // Update the wpcore_layer in website_data
        const pool = (await import('../config/db')).default;
        await pool.query(
          `UPDATE website_data SET wpcore_layer = $1, fetched_at = NOW() WHERE website_id = $2`,
          [coreCheckResult, website.id]
        );
        
        // Also update the core reinstall record status
        await pool.query(
          `UPDATE website_core_reinstalls SET status = $1, completed_at = NOW() WHERE operation_id = $2`,
          ['completed', operation_id]
        );
        
        logger.info({
          message: 'wpcore_layer updated after delayed core-check',
          domain,
          operation_id,
          websiteId: website.id
        }, {
          component: 'wordpress-controller',
          event: 'wpcore_layer_updated_after_core_reinstall'
        });
      } catch (coreErr) {
        logger.error({
          message: 'Failed to update wpcore_layer after delayed core-check',
          error: coreErr instanceof Error ? coreErr : new Error(String(coreErr) || 'Unknown error'),
          domain,
          operation_id,
          websiteId: website.id
        }, {
          component: 'wordpress-controller',
          event: 'wpcore_layer_update_failed_after_core_reinstall'
        });
      }
    }, 30000); // 30 second delay
    
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
    res.status(500).json({ error: err.message });
  }
});

export default router;
