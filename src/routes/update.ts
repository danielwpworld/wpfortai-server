import { Router } from 'express';
import { WPSecAPI } from '../services/wpsec';
import { getWebsiteByDomain } from '../config/db';
import { logger } from '../services/logger';

const router = Router();

// POST /api/update/:domain/all
router.post('/:domain/all', async (req, res) => {
  try {
    const { domain } = req.params;
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }
    const api = new WPSecAPI(domain);
    logger.info({ message: 'Calling updateAll', domain }, { component: 'update-controller', event: 'update_all_start' });
    await api.updateAll();
    logger.info({ message: 'updateAll succeeded', domain }, { component: 'update-controller', event: 'update_all_success' });

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
          websiteId: website.id
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
    logger.error({ message: 'updateAll failed', error: err }, { component: 'update-controller', event: 'update_all_error' });
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
    logger.info({ message: 'Calling updateItems', domain, type, itemSlugs }, { component: 'update-controller', event: 'update_items_start' });
    const updateResult = await api.updateItems(type, itemSlugs);
    logger.info({ message: 'updateItems succeeded', domain, type, itemSlugs, updateResult }, { component: 'update-controller', event: 'update_items_success' });

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
    logger.error({ message: 'updateItems failed', error: err }, { component: 'update-controller', event: 'update_items_error' });
    res.status(500).json({ error: err.message });
  }
});

export default router;
