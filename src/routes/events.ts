import { Router } from 'express';
import { getWebsiteByDomain } from '../config/db';
import pool from '../config/db';
import { broadcastToWebsite } from '../services/pusher';
import { logger } from '../services/logger';

const router = Router();

/**
 * Event creation endpoint that stores events in database and broadcasts them via Pusher
 * Expects:
 * - domain: Website domain
 * - event: Event name (e.g. wpcore_layer.core_reinstall.started)
 * - data: Event data with origin, vertical, and other metadata
 */
router.post('/create', async (req, res) => {
  try {
    const { domain, event, data } = req.body;

    if (!domain || !event || !data) {
      return res.status(400).json({ 
        error: 'Missing required parameters: domain, event, and data are required' 
      });
    }

    logger.debug({
      message: 'Received event for processing',
      domain,
      event
    }, {
      component: 'events',
      event: 'event_received'
    });

    // Get website ID from domain
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: `Website not found for domain: ${domain}` });
    }

    // Website ID is a UUID as per application requirements
    const websiteId = website.id.toString();

    // Extract event metadata from the data object
    const origin = data.origin || '';
    const vertical = data.vertical || '';
    const status = data.status || '';
    const message = data.message || '';
    
    // Store event in database
    const insertEventQuery = `
      INSERT INTO events (
        website_id, event_name, origin, vertical, 
        status, message, data
      ) 
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING id, created_at
    `;

    const eventResult = await pool.query(insertEventQuery, [
      websiteId, 
      event, 
      origin, 
      vertical, 
      status, 
      message, 
      JSON.stringify(data)
    ]);
    
    const eventId = eventResult.rows[0].id;
    const createdAt = eventResult.rows[0].created_at;

    logger.info({
      message: 'Successfully stored event',
      eventId,
      domain,
      websiteId,
      event,
      createdAt
    }, {
      component: 'events',
      event: 'event_stored'
    });

    // Broadcast the event via Pusher
    await broadcastToWebsite(websiteId, event, data);

    logger.info({
      message: 'Successfully broadcast event',
      eventId,
      domain,
      websiteId,
      event
    }, {
      component: 'events',
      event: 'event_broadcast'
    });

    return res.status(200).json({ 
      success: true, 
      message: 'Event created successfully',
      eventId,
      websiteId,
      channel: websiteId,
      event,
      createdAt
    });
    
  } catch (error: unknown) {
    const errorObj = error instanceof Error ? error : new Error(String(error));
    
    logger.error({
      message: 'Error processing event',
      error: errorObj
    }, {
      component: 'events',
      event: 'event_error'
    });

    return res.status(500).json({ 
      error: 'Failed to process event',
      message: errorObj.message
    });
  }
});

export default router;
