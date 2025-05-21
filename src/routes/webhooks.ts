import { Router } from 'express';
import { ScanStore } from '../services/scan-store';
import { WPSecAPI } from '../services/wpsec';
import type { ScanResults } from '../types/wpsec';
import { createWebsiteScanResult, getWebsiteByDomain, createScanDetection, updateWebsiteScanResult } from '../config/db';
import pool from '../config/db';
import { verifyWebhook } from '../middleware/verify-webhook';
import { WebhookSecrets } from '../services/webhook-secrets';
import { logger } from '../services/logger';

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

      // If there are detections, create a notification
      if (totalDetections > 0) {
        try {
          // Get website owner's UID
          const websiteResult = await pool.query(
            'SELECT uid FROM websites WHERE id = $1',
            [website.id]
          );
          
          if (websiteResult.rows.length > 0) {
            const ownerUid = websiteResult.rows[0].uid;
            
            // Create notification
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
    const { operation_id, status, message, completed_at } = req.body;
    if (!operation_id) {
      return res.status(400).json({ error: 'operation_id is required' });
    }
    await CoreReinstallStore.updateCoreReinstallStatus(operation_id, { status, message, completed_at });
    // Update DB as well
    try {
      const updateCoreReinstallRecord = (await import('../config/db')).updateCoreReinstallRecord;
      await updateCoreReinstallRecord(operation_id, { status, message });
    } catch (dbError) {
      const err = dbError instanceof Error ? dbError : new Error(String(dbError));
      logger.error({ message: 'Failed to update website_core_reinstalls record after core-reinstall-complete', error: err, operation_id }, {
        component: 'core-reinstall-webhook',
        event: 'core_reinstall_db_update_error'
      });
      // Do not fail the webhook if DB update fails, just log
    }
    res.json({ success: true });
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

export default router;
