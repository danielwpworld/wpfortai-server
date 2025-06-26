import { Router } from 'express';
import { getWebsiteByDomain } from '../config/db';
import { broadcastToWebsite } from '../services/pusher';
import { logger } from '../services/logger';

const router = Router();

/**
 * Webhook endpoint to receive events and broadcast them via Pusher
 * Expects:
 * - domain: Website domain
 * - event: Event name
 * - data: Event data
 */
router.post('/broadcast', async (req, res) => {
  try {
    const { domain, event, data } = req.body;

    if (!domain || !event || !data) {
      return res.status(400).json({ 
        error: 'Missing required parameters: domain, event, and data are required' 
      });
    }

    logger.debug({
      message: 'Received webhook event for broadcasting',
      domain,
      event
    }, {
      component: 'pusher-webhook',
      event: 'webhook_received'
    });

    // Get website ID from domain
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: `Website not found for domain: ${domain}` });
    }

    // Website ID is a UUID as per application requirements
    const websiteId = website.id.toString();

    // Set the standard event name
    const standardEventName = 'wpsec-activity-event';

    // Broadcast the event
    await broadcastToWebsite(websiteId, standardEventName, data);

    logger.info({
      message: 'Successfully broadcast event',
      domain,
      websiteId,
      event: standardEventName
    }, {
      component: 'pusher-webhook',
      event: 'broadcast_success'
    });

    return res.status(200).json({ 
      success: true, 
      message: 'Event broadcast successfully',
      websiteId,
      channel: websiteId,
      event: standardEventName
    });
  } catch (error: unknown) {
    const errorObj = error instanceof Error ? error : new Error(String(error));
    
    logger.error({
      message: 'Error broadcasting event',
      error: errorObj
    }, {
      component: 'pusher-webhook',
      event: 'broadcast_error'
    });

    return res.status(500).json({ 
      error: 'Failed to broadcast event',
      message: errorObj.message
    });
  }
});

export default router;
