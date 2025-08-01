import { Router } from 'express';
import { ScanStore } from '../services/scan-store';
import { WPSecAPI } from '../services/wpsec';
import type { ScanResults } from '../types/wpsec';
import { createWebsiteScanResult, getWebsiteByDomain, createScanDetection, updateWebsiteScanResult } from '../config/db';
import pool from '../config/db';
import { verifyWebhook } from '../middleware/verify-webhook';
import { WebhookSecrets } from '../services/webhook-secrets';
import { logger } from '../services/logger';
import { broadcastToWebsite } from '../services/pusher';
import { UpdateStore, UpdateItemStatus } from '../services/update-store';

const router = Router();

// --- Scan-related Webhook Middleware ---
import type { Request, Response, NextFunction } from 'express';

async function scanWebhookMiddleware(req: Request, res: Response, next: NextFunction) {
  try {
    logger.debug({ 
      message: 'Webhook request received',
      path: req.path,
      method: req.method,
      body: req.body
    }, {
      component: 'webhook-middleware'
    });
    const scanId = req.body.scan_id;
    if (!scanId) {
      return res.status(400).json({ error: 'scan_id is required' });
    }

    logger.debug({
      message: 'Fetching scan data from Redis',
      scanId
    }, {
      component: 'webhook-middleware',
      event: 'fetch_scan_start'
    });

    // Get scan data from Redis
    const scanData = await ScanStore.getScan(scanId);
    if (!scanData || !scanData.domain) {
      logger.warn({
        message: 'Scan not found in Redis or domain is missing',
        scanId,
        domain: scanData?.domain
      }, {
        component: 'webhook-middleware',
        event: 'scan_not_found'
      });
      return res.status(404).json({ error: 'Scan not found or domain is missing' });
    }

    logger.debug({
      message: 'Fetching website data',
      domain: scanData.domain,
      scanId
    }, {
      component: 'webhook-middleware',
      event: 'fetch_website_start'
    });

    // Get website
    const website = await getWebsiteByDomain(scanData.domain);
    if (!website) {
      logger.warn({
        message: 'Website not found',
        domain: scanData.domain,
        scanId
      }, {
        component: 'webhook-middleware',
        event: 'website_not_found'
      });
      return res.status(404).json({ error: 'Website not found' });
    }

    // BULLETPROOF CHECK: Verify scan belongs to the correct website
    // This prevents processing webhooks for scans from deleted/recreated websites
    if (scanData.website_id && scanData.website_id !== website.id) {
      logger.warn({
        message: 'Scan website_id mismatch - scan belongs to different website',
        scanId,
        scanWebsiteId: scanData.website_id,
        currentWebsiteId: website.id,
        domain: scanData.domain
      }, {
        component: 'webhook-middleware',
        event: 'website_id_mismatch'
      });
      return res.status(404).json({ error: 'Scan not found for this website' });
    }

    logger.debug({
      message: 'Fetching webhook secrets',
      websiteId: website.id,
      domain: scanData.domain,
      scanId
    }, {
      component: 'webhook-middleware',
      event: 'fetch_secrets_start'
    });

    // Get webhook secrets
    const secrets = await WebhookSecrets.getWebhookSecret(website.id);
    if (!secrets) {
      logger.warn({
        message: 'No webhook secret configured',
        websiteId: website.id,
        domain: scanData.domain,
        scanId
      }, {
        component: 'webhook-middleware',
        event: 'no_webhook_secret'
      });
      return res.status(401).json({ error: 'No webhook secret configured' });
    }

    logger.debug({
      message: 'Verifying webhook signature',
      websiteId: website.id,
      domain: scanData.domain,
      scanId,
      headers: {
        signature: req.headers['x-wpfort-signature'],
        timestamp: req.headers['x-wpfort-timestamp']
      }
    }, {
      component: 'webhook-middleware',
      event: 'verify_signature_start'
    });

    // Try current secret first
    try {
      verifyWebhook(secrets.currentSecret)(req, res, () => {
        logger.debug({
          message: 'Webhook signature verified with current secret',
          websiteId: website.id,
          domain: scanData.domain,
          scanId
        }, {
          component: 'webhook-middleware',
          event: 'signature_verified'
        });
        // Signature valid with current secret
        next();
      });
    } catch (e) {
      // If old secret exists and current secret failed, try old secret
      if (secrets.oldSecret) {
        logger.debug({
          message: 'Trying old secret for verification',
          websiteId: website.id,
          domain: scanData.domain,
          scanId
        }, {
          component: 'webhook-middleware',
          event: 'try_old_secret'
        });

        try {
          verifyWebhook(secrets.oldSecret)(req, res, () => {
            logger.debug({
              message: 'Webhook signature verified with old secret',
              websiteId: website.id,
              domain: scanData.domain,
              scanId
            }, {
              component: 'webhook-middleware',
              event: 'signature_verified_old'
            });
            // Signature valid with old secret
            next();
          });
        } catch (e) {
          // Both secrets failed
          return res.status(401).json({ error: 'Invalid webhook signature' });
        }
      } else {
        // No old secret to try
        return res.status(401).json({ error: 'Invalid webhook signature' });
      }
    }
  } catch (error) {
    logger.error({
      message: 'Error in webhook verification middleware',
      error: error instanceof Error ? error : new Error('Unknown error'),
      scanId: req.body.scan_id
    }, {
      component: 'webhook-middleware',
      event: 'webhook_error'
    });
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
  }
}

// --- SCAN WEBHOOKS ---
router.post('/scan-progress', scanWebhookMiddleware, async (req, res) => {
  try {
    logger.debug({
      message: 'Processing scan progress webhook',
      headers: req.headers,
      body: req.body
    }, {
      component: 'scan-progress-webhook',
      event: 'process_start'
    });

    logger.info({
      message: 'Scan progress webhook received',
      scanId: req.body.scan_id,
      status: req.body.status,
      progress: req.body.progress
    }, {
      component: 'scan-progress-webhook'
    });
    const { scan_id, status, progress } = req.body;
    if (!scan_id) {
      return res.status(400).json({ error: 'scan_id is required' });
    }

    // Get scan data from Redis
    const scanData = await ScanStore.getScan(scan_id);
    if (!scanData) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    // Update scan status in Redis
    const existingScan = await ScanStore.getScan(scan_id);
    if (!existingScan) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    await ScanStore.updateScanStatus(scan_id, {
      ...existingScan,
      status: status || existingScan.status,
      progress: progress ?? existingScan.progress ?? 0
    });

    res.json({ success: true });
  } catch (error) {
    console.error('Error processing scan progress webhook:', error);
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
  }
});

// Webhook for scan failed
router.post('/scan-failed', scanWebhookMiddleware, async (req, res) => {
  try {
    const { scan_id, error_message } = req.body;
    if (!scan_id) {
      return res.status(400).json({ error: 'scan_id is required' });
    }

    // Get scan data from Redis
    const scanData = await ScanStore.getScan(scan_id);
    if (!scanData || !scanData.domain) {
      return res.status(404).json({ error: 'Scan not found or domain is missing' });
    }

    // Get website from database
    const website = await getWebsiteByDomain(scanData.domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Update scan status in Redis
    await ScanStore.updateScanStatus(scan_id, {
      ...scanData,
      status: 'failed',
      error: error_message
    });

    // Store scan failure in database
    await createWebsiteScanResult(website.id, {
      scan_id,
      infected_files: 0,
      total_files: 0,
      started_at: new Date(scanData.started_at || Date.now()),
      completed_at: new Date(),
      duration: 0,
      status: 'failed',
      error_message
    });

    // Create and broadcast filesystem scan failed event
    try {
      // Construct event data
      const eventData = {
        origin: 'backend',
        vertical: 'filesystem_layer',
        status: 'failed',
        message: 'Deep file scan failed before completion.',
        metadata: {},
        scan_id,
        error: error_message || 'Unknown error occurred during scan',
        failed_at: new Date().toISOString()
      };
      
      // Create and broadcast the event
      const eventName = 'filesystem_layer.filesystem_scan.failed';
      
      // First store event in database, then broadcast
      // Use the event endpoint for consistency
      const eventResponse = await fetch(`http://localhost:${process.env.PORT || 3001}/api/events/create`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-wpfort-token': process.env.INTERNAL_API_TOKEN || '123123123'
        },
        body: JSON.stringify({
          domain: scanData.domain,
          event: eventName,
          data: eventData
        })
      });
      
      if (eventResponse.ok) {
        logger.info({
          message: 'Successfully created and broadcast scan failed event',
          scanId: scan_id,
          domain: scanData.domain,
          eventName
        }, {
          component: 'webhook',
          event: 'scan_event_created'
        });
      } else {
        logger.warn({
          message: 'Failed to create scan failed event',
          scanId: scan_id,
          domain: scanData.domain,
          eventName,
          status: eventResponse.status
        }, {
          component: 'webhook',
          event: 'scan_event_failed'
        });
      }
    } catch (eventError) {
      logger.error({
        message: 'Error creating scan failed event',
        error: eventError instanceof Error ? eventError : new Error(String(eventError)),
        scanId: scan_id,
        domain: scanData.domain
      }, {
        component: 'webhook',
        event: 'scan_event_error'
      });
      // Don't fail the webhook if event creation fails
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Error processing scan failed webhook:', error);
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
  }
});

// Webhook for scan completion
router.post('/scan-complete', scanWebhookMiddleware, async (req, res) => {
  try {
    const { scan_id } = req.body;
    if (!scan_id) {
      return res.status(400).json({ error: 'scan_id is required' });
    }

    // Get scan data from Redis
    const scanData = await ScanStore.getScan(scan_id);
    if (!scanData || !scanData.domain) {
      return res.status(404).json({ error: 'Scan not found or domain is missing' });
    }

    // Get website from database
    const website = await getWebsiteByDomain(scanData.domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    logger.debug({
      message: 'Website found',
      domain: scanData.domain,
      found: !!website
    });

    // Create WPSec API instance
    const api = new WPSecAPI(scanData.domain);

    // Update scan status in Redis to completed
    await ScanStore.updateScanStatus(scan_id, {
      ...scanData,
      status: 'completed',
      completed_at: new Date().toISOString()
    });

    // Fetch scan results
    let results;
    try {
      results = await api.getScanResults(scan_id);
      
      // Update scan results in database with data from WPSec API
      await updateWebsiteScanResult(website.id, scan_id, {
        infected_files: parseInt(results.infected_count) || 0,
        total_files: parseInt(results.total_files_scanned) || 0,
        completed_at: new Date(results.completed_at || Date.now()),
        duration: parseInt(results.duration) || 0,
        status: 'completed'
      });
    } catch (error) {
      logger.warn({
        message: 'Failed to fetch scan results from WPSec API',
        error: error instanceof Error ? error.message : 'Unknown error',
        scan_id,
        domain: scanData.domain
      });
      
      // Update basic scan results using data from Redis
      await updateWebsiteScanResult(website.id, scan_id, {
        infected_files: 0,
        total_files: parseInt(scanData.total_files || '0'),
        completed_at: new Date(),
        duration: 0,
        status: 'completed'
      });
    }

    // Store detections in database if results were fetched successfully
    if (results && results.infected_files) {
      // Count total detections
      let totalDetections = 0;
      for (const file of results.infected_files) {
        totalDetections += file.detections.length;
      }

      // If there are detections, create or update notification
      if (totalDetections > 0) {
        try {
          // Get website owner's UID
          const websiteResult = await pool.query(
            'SELECT uid FROM websites WHERE id = $1',
            [website.id]
          );
          
          if (websiteResult.rows.length > 0) {
            const ownerUid = websiteResult.rows[0].uid;
            const notificationType = 'malware_detection';
            
            // Check if notification of this type already exists for this website
            const existingNotificationResult = await pool.query(
              `SELECT id FROM user_notifications 
               WHERE website_id = $1 AND created_by = $2 AND uid = $3 AND title = $4`,
              [website.id, 'Sentinel', ownerUid, 'Infections detected - scan results']
            );
            
            if (existingNotificationResult.rows.length > 0) {
              // Update existing notification
              await pool.query(
                `UPDATE user_notifications 
                 SET description = $1, severity = $2, created_at = NOW(), read_at = NULL 
                 WHERE id = $3`,
                [
                  `${website.domain} is at risk`,
                  'Critical',
                  existingNotificationResult.rows[0].id
                ]
              );
              
              logger.info({
                message: 'Updated notification for scan detections',
                websiteId: website.id,
                scanId: scan_id,
                detectionsCount: totalDetections,
                ownerUid,
                notificationId: existingNotificationResult.rows[0].id
              }, {
                component: 'webhook',
                event: 'notification_updated'
              });
            } else {
              // Create new notification
              await pool.query(
                `INSERT INTO user_notifications 
                 (uid, title, description, severity, created_by, website_id, domain)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
                [
                  ownerUid,
                  'Infections detected - scan results',
                  `${website.domain} is at risk`,
                  'Critical',
                  'Sentinel',
                  website.id,  // Add website_id as UUID
                  website.domain  // Add domain
                ]
              );
              
              logger.info({
                message: 'Created notification for scan detections',
                websiteId: website.id,
                scanId: scan_id,
                detectionsCount: totalDetections,
                ownerUid
              }, {
                component: 'webhook',
                event: 'notification_created'
              });
            }
          }
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : String(error);
          logger.error({
            message: 'Error creating notification for scan detections',
            error: new Error(errorMessage),
            websiteId: website.id,
            scanId: scan_id
          }, {
            component: 'webhook',
            event: 'notification_error'
          });
          // Don't fail the webhook if notification creation fails
        }
      }
      
      logger.info({
        message: 'Processing scan detections',
        scanId: scan_id,
        domain: scanData.domain,
        infectedFilesCount: results.infected_files.length,
        totalDetections
      });
      
      // Use batch insert for large numbers of detections
      if (totalDetections > 10) {
        // Prepare all detections for batch insert
        const allDetections = [];
        for (const file of results.infected_files) {
          for (const detection of file.detections) {
            allDetections.push({
              file_path: file.file_path,
              threat_score: file.threat_score,
              confidence: file.confidence,
              detection_type: Array.isArray(detection.type) ? detection.type : [detection.type],
              severity: detection.severity,
              description: detection.description,
              file_hash: detection.file_hash,
              file_size: file.file_size,
              context_type: file.context.type,
              risk_level: file.context.risk_level
            });
          }
        }
        
        // Import the batch function and execute it
        const { batchCreateScanDetections } = await import('../config/db');
        await batchCreateScanDetections(String(website.id), scan_id, allDetections, 500);
        
        logger.info({
          message: 'Batch processed scan detections',
          scanId: scan_id,
          domain: scanData.domain,
          detectionCount: allDetections.length
        });
      } else {
        // For small numbers, use the original approach for better versioning support
        for (const file of results.infected_files) {
          for (const detection of file.detections) {
            await createScanDetection(website.id, scan_id, {
              file_path: file.file_path,
              threat_score: file.threat_score,
              confidence: file.confidence,
              detection_type: Array.isArray(detection.type) ? detection.type : [detection.type],
              severity: detection.severity,
              description: detection.description,
              file_hash: detection.file_hash,
              file_size: file.file_size,
              context_type: file.context.type,
              risk_level: file.context.risk_level
            });
          }
        }
      }
    }

    // Create and broadcast filesystem scan completion event
    try {
      // Get whether infections were found (detections above THREAT_SCORE_THRESHOLD)
      const threatScoreThreshold = parseInt(process.env.THREAT_SCORE_THRESHOLD || '80', 10);
      let infectionsFound = false;
      
      if (results && results.infected_files) {
        infectionsFound = results.infected_files.some(
          file => file.threat_score >= threatScoreThreshold
        );
      }
      
      // Construct event message based on scan results
      const eventMessage = infectionsFound
        ? 'Deep file scan completed. Infections detected.'
        : 'Deep file scan completed. Website is clean.';
      
      // Construct event data
      const eventData = {
        origin: 'backend',
        vertical: 'filesystem_layer',
        status: 'success',
        message: eventMessage,
        metadata: {},
        scan_id,
        infected_files_count: results?.infected_files?.length || 0,
        total_files_count: results?.total_files_scanned || 0,
        completed_at: new Date().toISOString()
      };
      
      // Create and broadcast the event
      const eventName = 'filesystem_layer.filesystem_scan.completed';
      
      // First store event in database, then broadcast
      // Use the event endpoint for consistency
      const eventResponse = await fetch(`http://localhost:${process.env.PORT || 3001}/api/events/create`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-wpfort-token': process.env.INTERNAL_API_TOKEN || '123123123'
        },
        body: JSON.stringify({
          domain: scanData.domain,
          event: eventName,
          data: eventData
        })
      });
      
      if (eventResponse.ok) {
        logger.info({
          message: 'Successfully created and broadcast scan completion event',
          scanId: scan_id,
          domain: scanData.domain,
          eventName
        }, {
          component: 'webhook',
          event: 'scan_event_created'
        });
      } else {
        logger.warn({
          message: 'Failed to create scan completion event',
          scanId: scan_id,
          domain: scanData.domain,
          eventName,
          status: eventResponse.status
        }, {
          component: 'webhook',
          event: 'scan_event_failed'
        });
      }
    } catch (eventError) {
      logger.error({
        message: 'Error creating scan completion event',
        error: eventError instanceof Error ? eventError : new Error(String(eventError)),
        scanId: scan_id,
        domain: scanData.domain
      }, {
        component: 'webhook',
        event: 'scan_event_error'
      });
      // Don't fail the webhook if event creation fails
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Error processing scan completion webhook:', error);
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
  }
});

// --- Core Reinstall Webhooks ---
import { CoreReinstallStore } from '../services/core-reinstall-store';

/**
 * Webhook: core-reinstall-progress
 * Body: { operation_id, status, message }
 */
router.post('/core-reinstall-progress', async (req, res) => {
  try {
    const { operation_id, status, message } = req.body;
    if (!operation_id) {
      return res.status(400).json({ error: 'operation_id is required' });
    }
    await CoreReinstallStore.updateCoreReinstallStatus(operation_id, { status, message });
    res.json({ success: true });
  } catch (error) {
    const err = error instanceof Error ? error : new Error(String(error));
    logger.error({ message: 'Error in core-reinstall-progress webhook', error: err });
    res.status(500).json({ error: err.message });
  }
});

/**
 * Webhook: core-reinstall-complete
 * Body: { operation_id, status, message, completed_at }
 */
router.post('/core-reinstall-complete', async (req, res) => {
  try {
    const { operation_id, status, message, completed_at, domain: requestDomain } = req.body;
    if (!operation_id) {
      return res.status(400).json({ error: 'operation_id is required' });
    }
    
    // Get domain from Redis if not provided in request
    let domain = requestDomain;
    if (!domain) {
      // Try to get the core reinstall data from Redis to extract the domain
      const reinstallData = await CoreReinstallStore.getCoreReinstall(operation_id);
      if (reinstallData && reinstallData.domain) {
        domain = reinstallData.domain;
        logger.info({
          message: 'Retrieved domain from Redis for core-reinstall-complete',
          operation_id,
          domain
        });
      } else {
        logger.error({
          message: 'Domain not provided and not found in Redis',
          operation_id
        });
        return res.status(400).json({ error: 'domain is required' });
      }
    }
    
    // First, get the website to ensure it exists and get its UUID
    const { getWebsiteByDomain } = await import('../config/db');
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      logger.error({
        message: 'Website not found for core-reinstall-complete webhook',
        domain,
        operation_id
      });
      return res.status(404).json({ error: 'Website not found' });
    }
    
    // Perform a core-check to get the latest core integrity data
    try {
      logger.info({
        message: 'Running core-check after core reinstall completion',
        domain,
        operation_id
      }, {
        component: 'core-reinstall-webhook',
        event: 'core_check_start'
      });
      
      const { WPSecAPI } = await import('../services/wpsec');
      const api = new WPSecAPI(domain);
      const coreCheckResult = await api.checkCoreIntegrity();
      
      // Update the wpcore_layer in website_data
      const pool = (await import('../config/db')).default;
      await pool.query(
        `UPDATE website_data SET wpcore_layer = $1, fetched_at = NOW() WHERE website_id = $2`,
        [coreCheckResult, website.id] // website.id is a UUID
      );
      
      logger.info({
        message: 'wpcore_layer updated after core-reinstall completion',
        domain,
        operation_id
      }, {
        component: 'core-reinstall-webhook',
        event: 'wpcore_layer_updated'
      });
      
      // Now update the Redis status and DB record - explicitly set status to 'completed'
      await CoreReinstallStore.updateCoreReinstallStatus(operation_id, { 
        status: 'completed', 
        message: message || 'Core reinstall completed successfully', 
        completed_at: completed_at || new Date().toISOString() 
      });
      
      // Update DB record as well
      const { updateCoreReinstallRecord } = await import('../config/db');
      await updateCoreReinstallRecord(operation_id, { 
        status: 'completed', 
        message: message || 'Core reinstall completed successfully' 
      });
      
      logger.info({
        message: 'Core reinstall marked as completed in Redis and database',
        domain,
        operation_id
      }, {
        component: 'core-reinstall-webhook',
        event: 'core_reinstall_completed'
      });
      
      // Create and broadcast core reinstall completed event
      try {
        // Construct event data
        const eventData = {
          origin: 'backend',
          vertical: 'wpcore_layer',
          status: 'success',
          message: 'WordPress system fix completed successfully.',
          operation_id,
          completed_at: new Date().toISOString()
        };
        
        // Create and broadcast the event
        const eventName = 'wpcore_layer.core_reinstall.completed';
        
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
            message: 'Successfully created and broadcast core reinstall completed event',
            domain,
            operation_id,
            eventName
          }, {
            component: 'core-reinstall-webhook',
            event: 'core_reinstall_completed_event_created'
          });
        } else {
          logger.warn({
            message: 'Failed to create core reinstall completed event',
            domain,
            operation_id,
            status: eventResponse.status
          }, {
            component: 'core-reinstall-webhook',
            event: 'core_reinstall_completed_event_failed'
          });
        }
      } catch (eventError) {
        logger.error({
          message: 'Error creating core reinstall completed event',
          error: eventError instanceof Error ? eventError : new Error(String(eventError)),
          domain,
          operation_id
        }, {
          component: 'core-reinstall-webhook',
          event: 'core_reinstall_completed_event_error'
        });
        // Don't fail the webhook if event creation fails
      }
      
      res.json({ success: true });
    } catch (coreCheckError) {
      const err = coreCheckError instanceof Error ? coreCheckError : new Error(String(coreCheckError));
      logger.error({
        message: 'Failed to perform core-check after core reinstall completion',
        error: err,
        domain,
        operation_id
      }, {
        component: 'core-reinstall-webhook',
        event: 'core_check_error'
      });
      
      // Still update Redis and DB with completed status even if core-check failed
      await CoreReinstallStore.updateCoreReinstallStatus(operation_id, { 
        status: 'completed', 
        message: message || 'Core reinstall completed but core-check failed', 
        completed_at: completed_at || new Date().toISOString() 
      });
      
      try {
        const { updateCoreReinstallRecord } = await import('../config/db');
        await updateCoreReinstallRecord(operation_id, { 
          status: 'completed', 
          message: message || 'Core reinstall completed but core-check failed' 
        });
        
        logger.info({
          message: 'Core reinstall marked as completed in Redis and database despite core-check failure',
          domain,
          operation_id
        }, {
          component: 'core-reinstall-webhook',
          event: 'core_reinstall_completed_with_errors'
        });
      } catch (dbError) {
        logger.error({
          message: 'Failed to update website_core_reinstalls record after core-reinstall-complete',
          error: dbError instanceof Error ? dbError : new Error(String(dbError)),
          operation_id
        }, {
          component: 'core-reinstall-webhook',
          event: 'core_reinstall_db_update_error'
        });
      }
      
      res.json({ success: true });
    }
  } catch (error) {
    const err = error instanceof Error ? error : new Error(String(error));
    logger.error({ message: 'Error in core-reinstall-complete webhook', error: err });
    res.status(500).json({ error: err.message });
  }
});

/**
 * Webhook: core-reinstall-failed
 * Body: { operation_id, status, error_message }
 */
router.post('/core-reinstall-failed', async (req, res) => {
  try {
    const { operation_id, status, error_message } = req.body;
    if (!operation_id) {
      return res.status(400).json({ error: 'operation_id is required' });
    }
    await CoreReinstallStore.updateCoreReinstallStatus(operation_id, { status, message: error_message });
    
    // Get domain from Redis since it's needed for the event
    let domain = req.body.domain;
    if (!domain) {
      // Try to get the core reinstall data from Redis to extract the domain
      const reinstallData = await CoreReinstallStore.getCoreReinstall(operation_id);
      if (reinstallData && reinstallData.domain) {
        domain = reinstallData.domain;
        logger.info({
          message: 'Retrieved domain from Redis for core-reinstall-failed event',
          operation_id,
          domain
        });
      } else {
        logger.error({
          message: 'Domain not provided and not found in Redis for event creation',
          operation_id
        });
        // We'll continue without creating the event
      }
    }
    
    // Create and broadcast core reinstall failed event if we have the domain
    if (domain) {
      try {
        // Construct event data
        const eventData = {
          origin: 'backend',
          vertical: 'wpcore_layer',
          status: 'failed',
          message: 'WordPress system fix failed.',
          operation_id,
          error: error_message || 'Unknown error',
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
            operation_id,
            eventName
          }, {
            component: 'core-reinstall-webhook',
            event: 'core_reinstall_failed_event_created'
          });
        } else {
          logger.warn({
            message: 'Failed to create core reinstall failed event',
            domain,
            operation_id,
            status: eventResponse.status
          }, {
            component: 'core-reinstall-webhook',
            event: 'core_reinstall_failed_event_failed'
          });
        }
      } catch (eventError) {
        logger.error({
          message: 'Error creating core reinstall failed event',
          error: eventError instanceof Error ? eventError : new Error(String(eventError)),
          domain,
          operation_id
        }, {
          component: 'core-reinstall-webhook',
          event: 'core_reinstall_failed_event_error'
        });
        // Don't fail the webhook if event creation fails
      }
    }
    
    // Update DB as well
    try {
      const updateCoreReinstallRecord = (await import('../config/db')).updateCoreReinstallRecord;
      await updateCoreReinstallRecord(operation_id, { status, message: error_message });
    } catch (dbError) {
      const err = dbError instanceof Error ? dbError : new Error(String(dbError));
      logger.error({ message: 'Failed to update website_core_reinstalls record after core-reinstall-failed', error: err, operation_id }, {
        component: 'core-reinstall-webhook',
        event: 'core_reinstall_db_update_error'
      });
      // Do not fail the webhook if DB update fails, just log
    }
    res.json({ success: true });
  } catch (error) {
    const err = error instanceof Error ? error : new Error(String(error));
    logger.error({ message: 'Error in core-reinstall-failed webhook', error: err });
    res.status(500).json({ error: err.message });
  }
});

// --- Update Webhooks ---

/**
 * Webhook: updates-progress
 * Body: { domain, items: [{ slug, status }] }
 */
router.post('/updates-progress', async (req, res) => {
  try {
    const { domain, items } = req.body;
    if (!domain) {
      return res.status(400).json({ error: 'domain is required' });
    }
    
    logger.info({
      message: 'Update progress webhook received',
      domain,
      items
    }, {
      component: 'update-progress-webhook',
      event: 'update_progress_received'
    });
    
    // Get update data from Redis
    const updateData = await UpdateStore.getActiveUpdate(domain);
    if (!updateData) {
      logger.warn({
        message: 'Update not found in Redis',
        domain
      }, {
        component: 'update-progress-webhook',
        event: 'update_not_found'
      });
      return res.status(404).json({ error: 'Update not found' });
    }
    
    // Update items status in Redis
    const itemUpdates: UpdateItemStatus[] = items.map((item: any) => ({
      slug: item.slug,
      status: item.status,
      error: item.error
    }));
    
    await UpdateStore.updateStatus(updateData.update_id, 'in-progress', itemUpdates);
    
    res.json({ success: true });
  } catch (error) {
    const err = error instanceof Error ? error : new Error(String(error));
    logger.error({
      message: 'Error processing update progress webhook',
      error: err
    }, {
      component: 'update-progress-webhook',
      event: 'update_progress_error'
    });
    res.status(500).json({ error: err.message });
  }
});

/**
 * Webhook: updates-completed
 * Body: { domain }
 */
router.post('/updates-completed', async (req, res) => {
  try {
    const { domain } = req.body;
    if (!domain) {
      return res.status(400).json({ error: 'domain is required' });
    }
    
    logger.info({
      message: 'Update completed webhook received',
      domain
    }, {
      component: 'update-completed-webhook',
      event: 'update_completed_received'
    });
    
    // Get update data from Redis
    const updateData = await UpdateStore.getActiveUpdate(domain);
    if (!updateData) {
      logger.warn({
        message: 'Update not found in Redis',
        domain
      }, {
        component: 'update-completed-webhook',
        event: 'update_not_found'
      });
      return res.status(404).json({ error: 'Update not found' });
    }
    
    // Mark update as completed in Redis
    await UpdateStore.updateStatus(updateData.update_id, 'completed');
    
    // Refresh vulnerabilities data in website_data
    try {
      const api = new WPSecAPI(updateData.domain);
      const applicationLayer = await api.getVulnerabilities();
      
      if (applicationLayer) {
        const pool = (await import('../config/db')).default;
        await pool.query(
          `UPDATE website_data SET application_layer = $1, fetched_at = NOW() WHERE website_id = $2`,
          [applicationLayer, updateData.website_id]
        );
        
        logger.info({
          message: 'Application layer updated after webhook completion',
          domain: updateData.domain,
          websiteId: updateData.website_id
        }, {
          component: 'update-completed-webhook',
          event: 'application_layer_updated'
        });
      }
    } catch (appErr) {
      const appError = appErr instanceof Error ? appErr : new Error(String(appErr));
      logger.error({
        message: 'Failed to update application_layer after webhook completion',
        error: appError,
        domain: updateData.domain,
        websiteId: updateData.website_id
      }, {
        component: 'update-completed-webhook',
        event: 'application_layer_update_failed'
      });
      // Do not fail the webhook if this step fails
    }
    
    res.json({ success: true });
  } catch (error) {
    const err = error instanceof Error ? error : new Error(String(error));
    logger.error({
      message: 'Error processing update completed webhook',
      error: err
    }, {
      component: 'update-completed-webhook',
      event: 'update_completed_error'
    });
    res.status(500).json({ error: err.message });
  }
});

/**
 * Webhook: update-backup-manifest
 * Body: { domain, manifest }
 * 
 * Updates the backup manifest for a website identified by domain.
 * If an entry exists, it updates the manifest column.
 * If no entry exists, it creates a new entry.
 */
router.post('/update-backup-manifest', async (req, res) => {
  try {
    const { domain, manifest } = req.body;
    
    if (!domain) {
      return res.status(400).json({ error: 'domain is required' });
    }
    
    if (!manifest) {
      return res.status(400).json({ error: 'manifest is required' });
    }
    
    logger.info({
      message: 'Update backup manifest webhook received',
      domain
    }, {
      component: 'update-backup-manifest-webhook',
      event: 'update_backup_manifest_received'
    });
    
    // Get website by domain to find the website_id
    const website = await getWebsiteByDomain(domain);
    
    if (!website) {
      logger.warn({
        message: 'Website not found',
        domain
      }, {
        component: 'update-backup-manifest-webhook',
        event: 'website_not_found'
      });
      return res.status(404).json({ error: 'Website not found' });
    }
    
    // Check if a backup manifest already exists for this website
    const existingManifestResult = await pool.query(
      'SELECT id FROM backup_manifests WHERE website_id = $1',
      [website.id]
    );
    
    if (existingManifestResult.rows.length > 0) {
      // Update existing manifest
      await pool.query(
        `UPDATE backup_manifests 
         SET manifest = $1, 
             domain = $2,
             created_at = NOW() 
         WHERE website_id = $3`,
        [manifest, domain, website.id]
      );
      
      logger.info({
        message: 'Updated existing backup manifest',
        domain,
        websiteId: website.id
      }, {
        component: 'update-backup-manifest-webhook',
        event: 'manifest_updated'
      });
    } else {
      // Create new backup manifest entry
      await pool.query(
        `INSERT INTO backup_manifests (website_id, manifest, domain, created_at)
         VALUES ($1, $2, $3, NOW())`,
        [website.id, manifest, domain]
      );
      
      logger.info({
        message: 'Created new backup manifest',
        domain,
        websiteId: website.id
      }, {
        component: 'update-backup-manifest-webhook',
        event: 'manifest_created'
      });
    }
    
    res.json({ success: true });
  } catch (error) {
    const err = error instanceof Error ? error : new Error(String(error));
    logger.error({
      message: 'Error processing update backup manifest webhook',
      error: err
    }, {
      component: 'update-backup-manifest-webhook',
      event: 'update_backup_manifest_error'
    });
    res.status(500).json({ error: err.message });
  }
});

// --- Individual Item Update Webhooks ---
// These webhooks support both update_id-based and domain-based identification

/**
 * Webhook: update-item-progress
 * Body: { update_id, slug, status, error? } OR { domain, slug, status, error? }
 */
router.post('/update-item-progress', async (req, res) => {
  try {
    const { update_id, domain, slug, status, error } = req.body;
    
    if ((!update_id && !domain) || !slug || !status) {
      return res.status(400).json({ error: 'Either update_id or domain is required, along with slug and status' });
    }
    
    logger.info({
      message: 'Update item progress webhook received',
      update_id,
      domain,
      slug,
      status,
      error
    }, {
      component: 'update-item-progress-webhook',
      event: 'update_item_progress_received'
    });
    
    // Get update data from Redis - try update_id first, then domain
    let updateData;
    if (update_id) {
      updateData = await UpdateStore.getUpdate(update_id);
    } else if (domain) {
      updateData = await UpdateStore.getActiveUpdate(domain);
    }
    if (!updateData) {
      logger.warn({
        message: 'Update not found in Redis',
        update_id,
        domain
      }, {
        component: 'update-item-progress-webhook',
        event: 'update_not_found'
      });
      return res.status(404).json({ error: 'Update not found' });
    }
    
    // Update item status in Redis
    const itemUpdate: UpdateItemStatus = {
      slug,
      status: status as UpdateItemStatus['status'],
      error
    };
    
    await UpdateStore.updateStatus(updateData.update_id, 'in-progress', [itemUpdate]);
    
    logger.info({
      message: 'Update item progress updated',
      update_id,
      slug,
      status,
      domain: updateData.domain
    }, {
      component: 'update-item-progress-webhook',
      event: 'update_item_progress_updated'
    });
    
    res.json({ success: true });
  } catch (error) {
    const err = error instanceof Error ? error : new Error(String(error));
    logger.error({
      message: 'Error processing update item progress webhook',
      error: err
    }, {
      component: 'update-item-progress-webhook',
      event: 'update_item_progress_error'
    });
    res.status(500).json({ error: err.message });
  }
});

/**
 * Webhook: update-item-complete
 * Body: { update_id, slug } OR { domain, slug }
 */
router.post('/update-item-complete', async (req, res) => {
  try {
    const { update_id, domain, slug } = req.body;
    
    if ((!update_id && !domain) || !slug) {
      return res.status(400).json({ error: 'Either update_id or domain is required, along with slug' });
    }
    
    logger.info({
      message: 'Update item complete webhook received',
      update_id,
      domain,
      slug
    }, {
      component: 'update-item-complete-webhook',
      event: 'update_item_complete_received'
    });
    
    // Get update data from Redis - try update_id first, then domain
    let updateData;
    if (update_id) {
      updateData = await UpdateStore.getUpdate(update_id);
    } else if (domain) {
      updateData = await UpdateStore.getActiveUpdate(domain);
    }
    if (!updateData) {
      logger.warn({
        message: 'Update not found in Redis',
        update_id,
        domain
      }, {
        component: 'update-item-complete-webhook',
        event: 'update_not_found'
      });
      return res.status(404).json({ error: 'Update not found' });
    }
    
    // Mark item as completed
    const itemUpdate: UpdateItemStatus = {
      slug,
      status: 'completed'
    };
    
    await UpdateStore.updateStatus(updateData.update_id, 'in-progress', [itemUpdate]);
    
    // Check if this was the last item to complete
    const updatedData = await UpdateStore.getUpdate(updateData.update_id);
    const allCompleted = updatedData && updatedData.items.every(item => 
      item.status === 'completed' || item.status === 'failed'
    );
    
    if (allCompleted) {
      logger.info({
        message: 'All items completed, updating application layer',
        update_id,
        domain: updateData.domain
      }, {
        component: 'update-item-complete-webhook',
        event: 'all_items_completed'
      });
      
      // Refresh vulnerabilities data in website_data when all items are done
      try {
        const api = new WPSecAPI(updateData.domain);
        const applicationLayer = await api.getVulnerabilities();
        
        if (applicationLayer) {
          const pool = (await import('../config/db')).default;
          await pool.query(
            `UPDATE website_data SET application_layer = $1, fetched_at = NOW() WHERE website_id = $2`,
            [applicationLayer, updateData.website_id]
          );
          
          logger.info({
            message: 'Application layer updated after item update completion',
            domain: updateData.domain,
            websiteId: updateData.website_id,
            update_id
          }, {
            component: 'update-item-complete-webhook',
            event: 'application_layer_updated'
          });
        }
      } catch (appErr) {
        const appError = appErr instanceof Error ? appErr : new Error(String(appErr));
        logger.error({
          message: 'Failed to update application_layer after item update completion',
          error: appError,
          domain: updateData.domain,
          update_id
        }, {
          component: 'update-item-complete-webhook',
          event: 'application_layer_update_failed'
        });
        // Do not fail the webhook if this step fails
      }

      // Create and broadcast completion event
      try {
        const completedItems = updatedData.items.filter(item => item.status === 'completed');
        const failedItems = updatedData.items.filter(item => item.status === 'failed');
        
        const eventData = {
          origin: 'backend',
          vertical: 'application_layer',
          status: failedItems.length === 0 ? 'success' : 'partial_success',
          message: failedItems.length === 0 
            ? (completedItems.length === 1 
                ? `${updateData.type === 'plugins' ? 'Plugin' : 'Theme'} updated successfully: ${completedItems[0].slug}`
                : `All ${completedItems.length} ${updateData.type || 'items'} updated successfully.`)
            : `${completedItems.length} ${updateData.type || 'items'} updated, ${failedItems.length} failed.`,
          update_id,
          completed_at: new Date().toISOString(),
          items: {
            type: updateData.type,
            completed: completedItems.length,
            failed: failedItems.length,
            total: updatedData.items.length
          }
        };
        
        const eventName = `application_layer.${updateData.type || 'plugins'}.update.completed`;
        
        const eventResponse = await fetch(`http://localhost:${process.env.PORT || 3001}/api/events/create`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-wpfort-token': process.env.INTERNAL_API_TOKEN || '123123123'
          },
          body: JSON.stringify({
            domain: updateData.domain,
            event: eventName,
            data: eventData
          })
        });
        
        if (eventResponse.ok) {
          logger.info({
            message: 'Successfully created and broadcast item update completed event',
            update_id,
            domain: updateData.domain,
            eventName
          }, {
            component: 'update-item-complete-webhook',
            event: 'update_completed_event_created'
          });
        }
      } catch (eventError) {
        logger.error({
          message: 'Error creating item update completed event',
          error: eventError instanceof Error ? eventError : new Error(String(eventError)),
          update_id,
          domain: updateData.domain
        }, {
          component: 'update-item-complete-webhook',
          event: 'update_completed_event_error'
        });
      }
    }
    
    logger.info({
      message: 'Update item marked as completed',
      update_id,
      slug,
      domain: updateData.domain
    }, {
      component: 'update-item-complete-webhook',
      event: 'update_item_completed'
    });
    
    res.json({ success: true });
  } catch (error) {
    const err = error instanceof Error ? error : new Error(String(error));
    logger.error({
      message: 'Error processing update item complete webhook',
      error: err
    }, {
      component: 'update-item-complete-webhook',
      event: 'update_item_complete_error'
    });
    res.status(500).json({ error: err.message });
  }
});

/**
 * Webhook: update-item-failed  
 * Body: { update_id, slug, error_message } OR { domain, slug, error_message }
 */
router.post('/update-item-failed', async (req, res) => {
  try {
    const { update_id, domain, slug, error_message } = req.body;
    
    if ((!update_id && !domain) || !slug) {
      return res.status(400).json({ error: 'Either update_id or domain is required, along with slug' });
    }
    
    logger.info({
      message: 'Update item failed webhook received',
      update_id,
      domain,
      slug,
      error_message
    }, {
      component: 'update-item-failed-webhook',
      event: 'update_item_failed_received'
    });
    
    // Get update data from Redis - try update_id first, then domain
    let updateData;
    if (update_id) {
      updateData = await UpdateStore.getUpdate(update_id);
    } else if (domain) {
      updateData = await UpdateStore.getActiveUpdate(domain);
    }
    if (!updateData) {
      logger.warn({
        message: 'Update not found in Redis',
        update_id,
        domain
      }, {
        component: 'update-item-failed-webhook',
        event: 'update_not_found'
      });
      return res.status(404).json({ error: 'Update not found' });
    }
    
    // Mark item as failed
    const itemUpdate: UpdateItemStatus = {
      slug,
      status: 'failed',
      error: error_message
    };
    
    await UpdateStore.updateStatus(updateData.update_id, 'in-progress', [itemUpdate]);
    
    const updatedData = await UpdateStore.getUpdate(updateData.update_id);
    const allDone = updatedData && updatedData.items.every(item => 
      item.status === 'completed' || item.status === 'failed'
    );
    
    if (allDone) {
      logger.info({
        message: 'All items processed (some failed), updating application layer',
        update_id,
        domain: updateData.domain
      }, {
        component: 'update-item-failed-webhook',
        event: 'all_items_processed'
      });
      
      // Still try to refresh application layer even if some items failed
      try {
        const api = new WPSecAPI(updateData.domain);
        const applicationLayer = await api.getVulnerabilities();
        
        if (applicationLayer) {
          const pool = (await import('../config/db')).default;
          await pool.query(
            `UPDATE website_data SET application_layer = $1, fetched_at = NOW() WHERE website_id = $2`,
            [applicationLayer, updateData.website_id]
          );
        }
      } catch (appErr) {
        logger.error({
          message: 'Failed to update application_layer after mixed update results',
          error: appErr instanceof Error ? appErr : new Error(String(appErr)),
          domain: updateData.domain,
          update_id
        }, {
          component: 'update-item-failed-webhook',
          event: 'application_layer_update_failed'
        });
      }

      // Create and broadcast completion event (with failures)
      try {
        const completedItems = updatedData.items.filter(item => item.status === 'completed');
        const failedItems = updatedData.items.filter(item => item.status === 'failed');
        
        const eventData = {
          origin: 'backend',
          vertical: 'application_layer',
          status: completedItems.length === 0 ? 'failed' : 'partial_success',
          message: completedItems.length === 0 
            ? (failedItems.length === 1 
                ? `${updateData.type === 'plugins' ? 'Plugin' : 'Theme'} failed to update: ${failedItems[0].slug}`
                : `All ${failedItems.length} ${updateData.type || 'items'} failed to update.`)
            : `${completedItems.length} ${updateData.type || 'items'} updated, ${failedItems.length} failed.`,
          update_id,
          completed_at: new Date().toISOString(),
          items: {
            type: updateData.type,
            completed: completedItems.length,
            failed: failedItems.length,
            total: updatedData.items.length
          },
          errors: failedItems.map(item => ({ slug: item.slug, error: item.error }))
        };
        
        const eventName = failedItems.length === updatedData.items.length 
          ? `application_layer.${updateData.type || 'plugins'}.update.failed`
          : `application_layer.${updateData.type || 'plugins'}.update.completed`;
        
        const eventResponse = await fetch(`http://localhost:${process.env.PORT || 3001}/api/events/create`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-wpfort-token': process.env.INTERNAL_API_TOKEN || '123123123'
          },
          body: JSON.stringify({
            domain: updateData.domain,
            event: eventName,
            data: eventData
          })
        });
        
        if (eventResponse.ok) {
          logger.info({
            message: 'Successfully created and broadcast item update completion event',
            update_id,
            domain: updateData.domain,
            eventName,
            completedCount: completedItems.length,
            failedCount: failedItems.length
          }, {
            component: 'update-item-failed-webhook',
            event: 'update_completion_event_created'
          });
        }
      } catch (eventError) {
        logger.error({
          message: 'Error creating item update completion event',
          error: eventError instanceof Error ? eventError : new Error(String(eventError)),
          update_id,
          domain: updateData.domain
        }, {
          component: 'update-item-failed-webhook',
          event: 'update_completion_event_error'
        });
      }
    }
    
    logger.info({
      message: 'Update item marked as failed',
      update_id,
      slug,
      error_message,
      domain: updateData.domain
    }, {
      component: 'update-item-failed-webhook',
      event: 'update_item_failed'
    });
    
    res.json({ success: true });
  } catch (error) {
    const err = error instanceof Error ? error : new Error(String(error));
    logger.error({
      message: 'Error processing update item failed webhook',
      error: err
    }, {
      component: 'update-item-failed-webhook',
      event: 'update_item_failed_error'
    });
    res.status(500).json({ error: err.message });
  }
});

export default router;
