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
  verify_checksums: true
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
