import { Router } from 'express';
import { WPSecAPI } from '../services/wpsec';
import { ScanStore } from '../services/scan-store';
import type { ScanStartResponse, ScanStatus, ScanResults, QuarantineResponse, QuarantineListResponse, QuarantineRestoreResponse, BatchOperationResponse } from '../types/wpsec';
import { getWebsiteByDomain, createWebsiteScanResult, updateScanDetectionStatus, updateScanDetectionByPath, createQuarantinedDetection, removeQuarantinedDetection, moveQuarantinedToDeleted, default as pool } from '../config/db';
import { logger } from '../services/logger';

const router = Router();

// Start a new scan
router.post('/:domain/start', async (req, res) => {
  try {
    const { domain } = req.params;

    logger.debug({
      message: 'Starting new scan',
      domain,
      body: req.body
    }, {
      component: 'scan-controller',
      event: 'scan_start_request'
    });
    
    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Check if there's already an active scan
    logger.debug({
      message: 'Checking for active scan',
      domain
    }, {
      component: 'scan-controller',
      event: 'check_active_scan'
    });

    const activeScan = await ScanStore.getActiveScan(domain);
    if (activeScan) {
      logger.info({
        message: 'Active scan already exists',
        domain,
        activeScanId: activeScan.scan_id
      }, {
        component: 'scan-controller',
        event: 'scan_already_active'
      });
      return res.status(409).json({ error: 'A scan is already in progress', scan_id: activeScan.scan_id });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Start scan
    logger.debug({
      message: 'Initiating scan with WPSec API',
      domain
    }, {
      component: 'scan-controller',
      event: 'wpsec_scan_start'
    });

    const scanData = await api.startScan();
    
    // Create initial scan record in database
    try {
      await createWebsiteScanResult(website.id, {
        scan_id: scanData.scan_id,
        infected_files: 0,
        total_files: 0,
        started_at: new Date(scanData.started_at),
        completed_at: new Date(0), // Will be updated when scan completes
        duration: 0,
        status: 'pending'
      });

      logger.info({
        message: 'Initial scan record created in database',
        domain,
        scanId: scanData.scan_id,
        websiteId: website.id
      }, {
        component: 'scan-controller',
        event: 'scan_record_created'
      });
    } catch (dbError) {
      logger.error({
        message: 'Failed to create initial scan record',
        error: dbError instanceof Error ? dbError : new Error('Unknown database error'),
        domain,
        scanId: scanData.scan_id
      }, {
        component: 'scan-controller',
        event: 'scan_record_error'
      });
      // Continue even if database insert fails
    }
    
    logger.info({
      message: 'Scan started successfully',
      domain,
      scanId: scanData.scan_id
    }, {
      component: 'scan-controller',
      event: 'scan_started'
    });

    res.json(scanData);
  } catch (error: any) {
    const errorDomain = req.params.domain;
    logger.error({
      message: 'Error starting scan',
      error,
      domain: errorDomain
    }, {
      component: 'scan-controller',
      event: 'scan_start_error'
    });
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
  }
});

// Get scan status
router.get('/:domain/status/:scanId', async (req, res) => {
  try {
    const { domain, scanId } = req.params;

    logger.debug({
      message: 'Getting scan status',
      domain,
      scanId
    }, {
      component: 'scan-controller',
      event: 'get_scan_status'
    });

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // First try to get scan status from Redis
    logger.debug({
      message: 'Fetching scan status from Redis',
      domain,
      scanId
    }, {
      component: 'scan-controller',
      event: 'fetch_scan_status_redis'
    });

    const redisScanData = await ScanStore.getScan(scanId);
    
    // If we have data in Redis, return it
    if (redisScanData) {
      logger.info({
        message: 'Scan status retrieved from Redis',
        domain,
        scanId,
        status: redisScanData.status,
        progress: redisScanData.progress
      }, {
        component: 'scan-controller',
        event: 'scan_status_from_redis'
      });

      // Format the response to match the expected structure
      const status = {
        status: redisScanData.status,
        progress: redisScanData.progress || 0,
        files_scanned: redisScanData.files_scanned || '0',
        total_files: redisScanData.total_files || '0',
        completed_at: redisScanData.completed_at,
        duration: redisScanData.duration || 0,
        error: redisScanData.error
      };

      return res.json(status);
    }
      
    // Modified: instead of WPSec API fallback, check database for scan status
    logger.debug({
      message: 'Scan not found in Redis, checking database',
      domain,
      scanId
    }, {
      component: 'scan-controller',
      event: 'fetch_scan_status_db'
    });
    const query = `
      SELECT status, started_at, completed_at, duration_seconds, infected_files_count, total_files_count, error_message
      FROM website_scans
      WHERE website_id = $1 AND scan_id = $2
    `;
    const dbResult = await pool.query(query, [website.id, scanId]);
    if (dbResult.rows.length > 0) {
      const dbScan = dbResult.rows[0];
      const statusFromDb = {
        status: dbScan.status,
        progress: dbScan.status === 'completed' ? 100 : 0,
        files_scanned: String(dbScan.infected_files_count || 0),
        total_files: String(dbScan.total_files_count || 0),
        completed_at: dbScan.completed_at?.toISOString(),
        duration: dbScan.duration_seconds || 0,
        error: dbScan.error_message
      };
      logger.info({
        message: 'Scan status retrieved from database',
        domain,
        scanId,
        status: statusFromDb.status
      }, {
        component: 'scan-controller',
        event: 'scan_status_from_db'
      });
      // Store in Redis for future requests
      await ScanStore.updateScanStatus(scanId, statusFromDb);
      return res.json(statusFromDb);
    }
    return res.status(404).json({ error: 'Scan not found' });
  } catch (error) {
    console.error('Error getting scan status:', error);
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
  }
});

// Get scan results
router.get('/:domain/results/:scanId', async (req, res) => {
  try {
    const { domain, scanId } = req.params;

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Get scan results
    logger.debug({
      message: 'Fetching scan results from WPSec API',
      domain,
      scanId
    }, {
      component: 'scan-controller',
      event: 'fetch_scan_results'
    });

    const results = await api.getScanResults(scanId);

    logger.info({
      message: 'Scan results retrieved',
      domain,
      scanId,
      totalIssues: (results as any).issues?.length || 0,
      totalFiles: (results as any).files?.length || 0
    }, {
      component: 'scan-controller',
      event: 'scan_results_retrieved'
    });

    res.json(results);
  } catch (error) {
    console.error('Error getting scan results:', error);
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
  }
});

// Get latest scan for a domain
router.get('/:domain/latest-scan', async (req, res) => {
  try {
    const { domain } = req.params;
    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }
    // Query for the latest scan (order by started_at DESC)
    const query = `
      SELECT * FROM website_scans
      WHERE website_id = $1
      ORDER BY started_at DESC
      LIMIT 1
    `;
    const result = await pool.query(query, [website.id]);
    if (result.rows.length === 0) {
      logger.debug({
        message: 'No scans found for domain',
        domain,
        websiteId: website.id
      }, {
        component: 'scan-controller',
        event: 'no_scans_found'
      });
      return res.json({ 
        status: 'success', 
        message: 'No scans performed yet',
        latest_scan: null 
      });
    }
    logger.debug({
      message: 'Fetched latest scan for domain',
      domain,
      websiteId: website.id,
      scan: result.rows[0]
    }, {
      component: 'scan-controller',
      event: 'get_latest_scan'
    });
    res.json({ status: 'success', latest_scan: result.rows[0] });
  } catch (error) {
    logger.error({
      message: 'Error fetching latest scan',
      error: error instanceof Error ? error : new Error(String(error) || 'Unknown error'),
      domain: req.params.domain
    }, {
      component: 'scan-controller',
      event: 'get_latest_scan_error'
    });
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
  }
});

// Get active scan for a domain
router.get('/:domain/active', async (req, res) => {
  try {
    const { domain } = req.params;

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Get active scan
    logger.debug({
      message: 'Checking for active scan',
      domain
    }, {
      component: 'scan-controller',
      event: 'check_active_scan'
    });

    const activeScan = await ScanStore.getActiveScan(domain);
    if (!activeScan) {
      logger.info({
        message: 'No active scan found',
        domain
      }, {
        component: 'scan-controller',
        event: 'no_active_scan'
      });
      return res.status(404).json({ error: 'No active scan found' });
    }

    res.json(activeScan);
  } catch (error) {
    console.error('Error getting active scan:', error);
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
  }
});

// Quarantine a single file
router.post('/:domain/quarantine', async (req, res) => {
  try {
    const { domain } = req.params;
    const { file_path, scan_detection_id, scan_finding_id } = req.body;
    let foundScanDetectionId = null;

    if (!file_path) {
      return res.status(400).json({ error: 'file_path is required' });
    }

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Quarantine file
    logger.debug({
      message: 'Quarantining file',
      domain,
      filePath: file_path,
      scanDetectionId: scan_detection_id,
      scanFindingId: scan_finding_id
    }, {
      component: 'scan-controller',
      event: 'quarantine_file'
    });

    // Call the WPSec API to quarantine the file
    const result = await api.quarantineFile(file_path);
    let detectionUpdate: any = null;

    // --- ENHANCED LOGIC: Update all relevant scan_detections and insert into quarantined_detections ---
    // Find all scan_detections for this website, file_path, and file_hash
    const detectionResult = await pool.query(
      `SELECT * FROM scan_detections WHERE website_id = $1 AND file_path = $2 AND file_hash = $3`,
      [website.id, file_path, req.body.file_hash]
    );
    if (detectionResult.rows.length === 0) {
      return res.status(404).json({ error: 'No scan detection found for file' });
    }

    // Update all matching scan_detections.status to 'quarantined'
    const updateQuery = `
      UPDATE scan_detections SET status = 'quarantined'
      WHERE website_id = $1 AND file_path = $2 AND file_hash = $3`;
    await pool.query(updateQuery, [website.id, file_path, req.body.file_hash]);

    // Find the latest detection to use for the quarantined_detections entry
    const latestDetectionQuery = `
      SELECT * FROM scan_detections 
      WHERE website_id = $1 AND file_path = $2 AND file_hash = $3
      ORDER BY created_at DESC LIMIT 1`;
    const latestResult = await pool.query(latestDetectionQuery, [website.id, file_path, req.body.file_hash]);
    
    if (latestResult.rows.length > 0) {
      const latestDetection = latestResult.rows[0];
      
      // Insert only one entry into quarantined_detections for the latest detection
      await createQuarantinedDetection({
        scan_detection_id: latestDetection.id,
        quarantine_id: result.quarantine_id,
        original_path: latestDetection.file_path,
        quarantine_path: result.quarantine_path || 'unknown',
        timestamp: new Date(),
        scan_finding_id: latestDetection.scan_finding_id || null,
        file_size: latestDetection.file_size || 0,
        file_type: latestDetection.file_type || 'unknown',
        file_hash: latestDetection.file_hash || null,
        detection_type: latestDetection.detection_type ? (Array.isArray(latestDetection.detection_type) ? latestDetection.detection_type : [latestDetection.detection_type]) : ['manual'],
        confidence: latestDetection.confidence || 0,
        threat_score: latestDetection.threat_score || 0
      });
    }

    logger.info({
      message: 'File quarantined successfully',
      domain,
      filePath: file_path,
      quarantineId: result.quarantine_id
    }, {
      component: 'scan-controller',
      event: 'file_quarantined'
    });

    res.json({ status: 'success', quarantine_id: result.quarantine_id });
  } catch (error) {
    console.error('Error quarantining file:', error);
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
  }
});

// Get quarantined files
router.get('/:domain/quarantine', async (req, res) => {
  try {
    const { domain } = req.params;

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    logger.debug({
      message: 'Retrieving quarantined files from database',
      domain,
      websiteId: website.id
    }, {
      component: 'scan-controller',
      event: 'get_quarantined_files'
    });

    // Query the quarantined_detections table
    // We need to handle records with null scan_detection_id
    const query = `
      SELECT qd.*, sd.scan_id, sd.detection_type as scan_detection_type, sd.status as scan_detection_status
      FROM quarantined_detections qd
      LEFT JOIN scan_detections sd ON qd.scan_detection_id = sd.id
      WHERE 
        (sd.website_id = $1) OR 
        (qd.scan_detection_id IS NULL AND EXISTS (
          SELECT 1 FROM websites w WHERE w.domain = $2
        ))
      ORDER BY qd.timestamp DESC
    `;
    
    const result = await pool.query(query, [website.id, domain]);
    
    logger.debug({
      message: 'Retrieved quarantined files',
      domain,
      count: result.rows.length
    }, {
      component: 'scan-controller',
      event: 'quarantined_files_retrieved'
    });
    
    res.json({
      status: 'success',
      quarantined_files: result.rows
    });
  } catch (error) {
    const err = error instanceof Error ? error : new Error(String(error) || 'Unknown error');
    logger.error({
      message: 'Error getting quarantined files',
      error: err,
      domain: req.params.domain
    }, {
      component: 'scan-controller',
      event: 'get_quarantined_files_error'
    });
    res.status(500).json({ error: err.message });
  }
});

// Add file to whitelist
router.post('/:domain/whitelist', async (req, res) => {
  try {
    const { domain } = req.params;
    const { file_path, reason, added_by } = req.body;
    
    // Handle both single file path and array of file paths
    const filePaths = Array.isArray(file_path) ? file_path : [file_path];
    
    logger.debug({
      message: 'Adding file(s) to whitelist',
      domain,
      filePath: file_path,
      fileCount: filePaths.length,
      reason,
      addedBy: added_by
    }, {
      component: 'whitelist-controller',
      event: 'add_to_whitelist'
    });
    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }
    // Create WPSec API instance
    const api = new WPSecAPI(domain);
    logger.info({
      message: 'Calling api.whitelistFile',
      domain,
      filePath: file_path,
      fileCount: filePaths.length,
      reason,
      addedBy: added_by
    }, {
      component: 'whitelist-controller',
      event: 'whitelist_api_call_start'
    });
    try {
      const result = await api.whitelistFile(file_path, reason, added_by);
      logger.info({
        message: 'api.whitelistFile succeeded',
        domain,
        filePath: file_path,
        fileCount: filePaths.length,
        reason,
        addedBy: added_by,
        apiResult: result
      }, {
        component: 'whitelist-controller',
        event: 'whitelist_api_call_success'
      });
    } catch (apiError) {
      const errorMsg = apiError instanceof Error ? apiError.message : String(apiError);
      logger.error({
        message: 'api.whitelistFile failed',
        domain,
        filePath: file_path,
        fileCount: filePaths.length,
        reason,
        addedBy: added_by
      }, {
        component: 'whitelist-controller',
        event: 'whitelist_api_call_error'
      });
      return res.status(502).json({ error: 'Failed to whitelist file(s) on WPSec site', details: errorMsg });
    }
    // --- Update scan_detections and insert into whitelisted_detections ---
    const whitelistedResults = [];
    
    // Process each file path
    for (const singleFilePath of filePaths) {
      try {
        // Get file hash from request body if it's a single file, or use undefined if it's an array
        // For array case, we'll just use the file path for the query
        const fileHash = !Array.isArray(req.body.file_path) ? req.body.file_hash : undefined;
        
        let detectionQuery;
        let detectionParams;
        
        if (fileHash) {
          detectionQuery = `SELECT * FROM scan_detections WHERE website_id = $1 AND file_path = $2 AND file_hash = $3`;
          detectionParams = [website.id, singleFilePath, fileHash];
        } else {
          detectionQuery = `SELECT * FROM scan_detections WHERE website_id = $1 AND file_path = $2`;
          detectionParams = [website.id, singleFilePath];
        }
        
        const detectionResult = await pool.query(detectionQuery, detectionParams);
        
        if (detectionResult.rows.length === 0) {
          logger.warn({
            message: 'No scan detection found for file',
            domain,
            filePath: singleFilePath
          }, {
            component: 'whitelist-controller',
            event: 'whitelist_no_detection'
          });
          continue; // Skip to next file
        }
        
        // Update scan_detections status
        const updateQuery = `
          UPDATE scan_detections SET status = 'whitelisted'
          WHERE website_id = $1 AND file_path = $2`;
        await pool.query(updateQuery, [website.id, singleFilePath]);
        
        const detection = detectionResult.rows[0];
        
        // Insert into whitelisted_detections
        const insertQuery = `
          INSERT INTO whitelisted_detections (
            website_id, scan_detection_id, file_path, file_hash, file_size, detection_type, reason, whitelisted_at, confidence, threat_score
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), $8, $9)
          ON CONFLICT (website_id, file_path) DO UPDATE SET reason = EXCLUDED.reason, whitelisted_at = NOW(), confidence = EXCLUDED.confidence, threat_score = EXCLUDED.threat_score
          RETURNING *
        `;
        
        const insertValues = [
          website.id,
          detection.id,
          detection.file_path,
          detection.file_hash,
          detection.file_size,
          detection.detection_type,
          reason || null,
          detection.confidence || 0,
          detection.threat_score || 0
        ];
        
        const whitelistedRes = await pool.query(insertQuery, insertValues);
        whitelistedResults.push(whitelistedRes.rows[0]);
      } catch (fileError) {
        logger.error({
          message: 'Error processing individual file for whitelist',
          domain,
          filePath: singleFilePath,
          error: fileError instanceof Error ? fileError : new Error(String(fileError))
        }, {
          component: 'whitelist-controller',
          event: 'whitelist_file_error'
        });
        // Continue processing other files even if one fails
      }
    }
    
    logger.info({
      message: `${whitelistedResults.length} file(s) added to whitelist successfully`,
      domain,
      filePaths,
      successCount: whitelistedResults.length,
      totalCount: filePaths.length,
      reason,
      addedBy: added_by
    }, {
      component: 'whitelist-controller',
      event: 'files_whitelisted'
    });
    
    res.json({ 
      status: 'success', 
      whitelisted: whitelistedResults,
      summary: {
        total: filePaths.length,
        successful: whitelistedResults.length
      }
    });
  } catch (error: any) {
    const errorDomain = req.params.domain;
    logger.error({
      message: 'Error adding file to whitelist',
      error,
      domain: errorDomain,
      filePath: req.body.file_path
    }, {
      component: 'whitelist-controller',
      event: 'whitelist_error'
    });
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
  }
});

// Remove file from whitelist
router.post('/:domain/whitelist/remove', async (req, res) => {
  try {
    const { domain } = req.params;
    const { file_path, file_hash } = req.body;
    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }
    // Create WPSec API instance
    const api = new WPSecAPI(domain);
    await api.removeWhitelistedFile(file_path);
    // Update all scan_detections for this file_path and file_hash to 'active'
    const updateQuery = `
      UPDATE scan_detections SET status = 'active'
      WHERE website_id = $1 AND file_path = $2 AND file_hash = $3`;
    await pool.query(updateQuery, [website.id, file_path, file_hash]);
    // Remove from whitelisted_detections
    const deleteQuery = `
      DELETE FROM whitelisted_detections
      WHERE website_id = $1 AND file_path = $2 AND file_hash = $3`;
    await pool.query(deleteQuery, [website.id, file_path, file_hash]);
    res.json({ success: true });
  } catch (error) {
    console.error('Error removing file from whitelist:', error);
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
  }
});

// Verify whitelist integrity
router.get('/:domain/whitelist/verify', async (req, res) => {
  try {
    const { domain } = req.params;
    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }
    // Create WPSec API instance
    const api = new WPSecAPI(domain);
    const result = await api.verifyWhitelistIntegrity();
    res.json(result);
  } catch (error) {
    console.error('Error verifying whitelist integrity:', error);
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
  }
});

// Cleanup whitelist
router.post('/:domain/whitelist/cleanup', async (req, res) => {
  try {
    const { domain } = req.params;
    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }
    // Create WPSec API instance
    const api = new WPSecAPI(domain);
    await api.cleanupWhitelist();
    res.json({ success: true });
  } catch (error) {
    console.error('Error cleaning up whitelist:', error);
    const err = error instanceof Error ? error : new Error('Unknown error');
    res.status(500).json({ error: err.message });
  }
});

// Fetch whitelisted files
router.get('/:domain/whitelist', async (req, res) => {
  try {
    const { domain } = req.params;
    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }
    // Fetch all whitelisted files for this website
    const query = `
      SELECT * FROM whitelisted_detections WHERE website_id = $1 ORDER BY whitelisted_at DESC
    `;
    const result = await pool.query(query, [website.id]);
    res.json({ whitelisted_files: result.rows });
  } catch (error) {
    const err = error instanceof Error ? error : new Error(String(error) || 'Unknown error');
    logger.error({
      message: 'Error getting whitelisted files',
      error: err,
      domain: req.params.domain
    }, {
      component: 'scan-controller',
      event: 'get_whitelisted_files_error'
    });
    res.status(500).json({ error: err.message });
  }
});

// Restore quarantined file
router.post('/:domain/quarantine/restore', async (req, res) => {
  try {
    const { domain } = req.params;
    const { quarantine_id, quarantine_ids } = req.body;
    const ids = Array.isArray(quarantine_ids)
      ? quarantine_ids
      : quarantine_id
        ? [quarantine_id]
        : [];
    if (!ids.length) {
      return res.status(400).json({ error: 'quarantine_id or quarantine_ids is required' });
    }

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    logger.debug({
      message: 'Restoring file from quarantine',
      domain,
      quarantineIds: ids
    }, {
      component: 'scan-controller',
      event: 'restore_from_quarantine'
    });

    // Enhanced restore logic: For each quarantine_id, mark all related scan_detections as 'active' and remove all corresponding quarantined_detections
    // Track if any DB error occurs
    let dbErrorOccurred = false;
    let dbErrorDetails: any = null;
    for (const id of ids) {
      try {
        // Get the quarantined detection record
        const getQuery = `SELECT * FROM quarantined_detections WHERE quarantine_id = $1`;
        const getResult = await pool.query(getQuery, [id]);
        if (getResult.rows.length === 0) continue;
        const qd = getResult.rows[0];
        
        // If we have a scan_detection_id, update its status to 'active'
        if (qd.scan_detection_id) {
          const updateQuery = `UPDATE scan_detections SET status = 'active' WHERE id = $1`;
          await pool.query(updateQuery, [qd.scan_detection_id]);
        }
        
        // Remove the quarantined detection by quarantine_id
        const deleteQuery = `DELETE FROM quarantined_detections WHERE quarantine_id = $1`;
        await pool.query(deleteQuery, [id]);
        
        logger.debug({
          message: 'Restored scan detection and removed quarantined detection',
          quarantineId: id,
          scanDetectionId: qd.scan_detection_id,
          filePath: qd.original_path,
          fileHash: qd.file_hash
        }, {
          component: 'scan-controller',
          event: 'restore_from_quarantine'
        });
      } catch (dbError) {
        dbErrorOccurred = true;
        dbErrorDetails = dbError instanceof Error ? dbError : new Error(String(dbError) || 'Unknown error');
        logger.error({
          message: 'Failed to restore scan detection or remove quarantined detection',
          error: dbErrorDetails,
          quarantineId: id
        }, {
          component: 'scan-controller',
          event: 'restore_from_quarantine_error'
        });
        break; // Stop processing further if any error occurs
      }
    }

    if (dbErrorOccurred) {
      return res.status(500).json({
        message: 'Failed to restore all matching scan detections or remove quarantined detections',
        error: dbErrorDetails?.message || 'Unknown error',
        quarantineIds: ids
      });
    }

    // Now restore the file(s) via the WPSec API
    const result = await api.restoreQuarantinedFile(ids);

    logger.info({
      message: 'File restored from quarantine successfully',
      domain,
      quarantineIds: ids
    }, {
      component: 'scan-controller',
      event: 'file_restored'
    });

    res.json(result);
  } catch (error) {
    console.error('Error restoring quarantined file:', error);
    const err = error instanceof Error ? error : new Error(String(error) || 'Unknown error');
    const domainParam = req.params.domain;
    logger.error({
      message: 'Error restoring quarantined file',
      error: err,
      domain: domainParam,
      quarantineIds: req.body.quarantine_ids || req.body.quarantine_id
    }, {
      component: 'scan-controller',
      event: 'restore_file_error'
    });
    res.status(500).json({ error: err.message });
  }
});

// Batch delete/quarantine files
router.post('/:domain/batch-operation', async (req, res) => {
  try {
    const { domain } = req.params;
    const { operation, files, scan_detection_ids, quarantine_ids } = req.body;

    // Validate operation
    if (!['delete', 'quarantine'].includes(operation)) {
      return res.status(400).json({ error: 'Invalid operation. Must be either "delete" or "quarantine".' });
    }

    if (!files || !Array.isArray(files) || files.length === 0) {
      return res.status(400).json({ error: 'Files array is required and must not be empty' });
    }

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);
    
    // If operation is delete, add permanent_deletion: "yes" flag to all files
    if (operation === 'delete') {
      for (let i = 0; i < files.length; i++) {
        files[i].permanent_deletion = "yes";
      }
    }

    // If operation is delete and we have quarantined files, modify the file paths to use quarantine_path
    if (operation === 'delete' && quarantine_ids && Array.isArray(quarantine_ids) && quarantine_ids.length > 0) {
      // Process each quarantined file
      for (let i = 0; i < quarantine_ids.length; i++) {
        const quarantineId = quarantine_ids[i];
        if (!quarantineId) continue;
        
        try {
          // Get the quarantined file details
          const getQuery = `
            SELECT * FROM quarantined_detections 
            WHERE quarantine_id = $1
          `;
          
          const getResult = await pool.query(getQuery, [quarantineId]);
          
          if (getResult.rows.length > 0) {
            const quarantinedFile = getResult.rows[0];
            
            // Update the file path to use the quarantine_path instead of original_path
            if (files[i] && files[i].file_path) {
              files[i].file_path = quarantinedFile.quarantine_path;
              
              logger.debug({
                message: 'Updated file path to use quarantine_path for batch delete operation',
                originalPath: quarantinedFile.original_path,
                quarantinePath: quarantinedFile.quarantine_path,
                quarantineId
              }, {
                component: 'scan-controller',
                event: 'batch_update_file_path'
              });
            }
          }
        } catch (dbError) {
          // Ensure dbError is always an Error object
          const err = dbError instanceof Error ? dbError : new Error(String(dbError) || 'Unknown error');
          logger.error({
            message: 'Failed to get quarantined file details',
            error: err,
            quarantineId
          }, {
            component: 'scan-controller',
            event: 'batch_get_quarantined_file_error'
          });
        }
      }
    }

    logger.debug({
      message: `Processing batch ${operation} operation`,
      domain,
      fileCount: files.length,
      operation,
      hasQuarantineIds: quarantine_ids && quarantine_ids.length > 0
    }, {
      component: 'scan-controller',
      event: 'batch_operation'
    });

    // Process batch operation
    const result = await api.batchFileOperation(operation, files);

    // Enhanced batch logic for quarantine and delete
    if (operation === 'quarantine' && result.status === 'success') {
      // For each quarantined file, mark all past detections as quarantined and insert into quarantined_detections
      for (let i = 0; i < result.results.success.length; i++) {
        const successItem = result.results.success[i];
        const filePath = successItem.file_path;
        const quarantineResult = successItem.result;
        // Try to get file_hash from quarantineResult, else from input
        // Type guard for quarantineResult
        let fileHash: string | undefined = undefined;
        if (quarantineResult && typeof quarantineResult === 'object' && 'file_hash' in quarantineResult) {
          fileHash = quarantineResult.file_hash ?? undefined;
        } else {
          fileHash = files[i]?.file_hash ?? undefined;
        }
        if (!fileHash) {
          // Try to get the latest file_hash from scan_detections
          const hashResult = await pool.query(
            `SELECT file_hash FROM scan_detections WHERE website_id = $1 AND file_path = $2 ORDER BY created_at DESC LIMIT 1`,
            [website.id, filePath]
          );
          if (hashResult.rows.length > 0) fileHash = hashResult.rows[0].file_hash;
        }
        if (!fileHash) {
          logger.warn({
            message: 'No file_hash found for file_path in batch quarantine',
            filePath,
            websiteId: website.id
          }, {
            component: 'scan-controller',
            event: 'batch_quarantine_missing_hash'
          });
          continue;
        }
        // Get all detections for this file
        const detectionResult = await pool.query(
          `SELECT * FROM scan_detections WHERE website_id = $1 AND file_path = $2 AND file_hash = $3`,
          [website.id, filePath, fileHash]
        );
        // Mark all as quarantined
        await pool.query(
          `UPDATE scan_detections SET status = 'quarantined' WHERE website_id = $1 AND file_path = $2 AND file_hash = $3`,
          [website.id, filePath, fileHash]
        );
        // Insert into quarantined_detections for each
        for (const detection of detectionResult.rows) {
          let quarantineId = 'unknown';
          let quarantinePath = 'unknown';
          if (quarantineResult && typeof quarantineResult === 'object') {
            if ('quarantine_id' in quarantineResult && quarantineResult.quarantine_id) {
              quarantineId = quarantineResult.quarantine_id;
            }
            if ('quarantine_path' in quarantineResult && quarantineResult.quarantine_path) {
              quarantinePath = quarantineResult.quarantine_path;
            }
          }
          await createQuarantinedDetection({
            scan_detection_id: detection.id,
            quarantine_id: quarantineId,
            original_path: detection.file_path,
            quarantine_path: quarantinePath,
            timestamp: new Date(),
            scan_finding_id: detection.scan_finding_id || null,
            file_size: detection.file_size || 0,
            file_type: detection.file_type || 'unknown',
            file_hash: detection.file_hash || null,
            detection_type: detection.detection_type ? (Array.isArray(detection.detection_type) ? detection.detection_type : [detection.detection_type]) : ['batch'],
            confidence: detection.confidence || 0,
            threat_score: detection.threat_score || 0
          });
        }
        logger.info({
          message: 'Batch: Marked all past detections as quarantined and created quarantined_detections records',
          websiteId: website.id,
          filePath,
          fileHash
        }, {
          component: 'scan-controller',
          event: 'batch_quarantine_bulk_update'
        });
      }
    }
    if (operation === 'delete' && result.status === 'success') {
      // For each deleted file, mark all past detections as deleted and insert into deleted_detections
      for (let i = 0; i < files.length; i++) {
        const filePath = files[i]?.file_path;
        if (!filePath) continue;
        let fileHash = files[i]?.file_hash;
        if (!fileHash) {
          // Try to get the latest file_hash from scan_detections
          const hashResult = await pool.query(
            `SELECT file_hash FROM scan_detections WHERE website_id = $1 AND file_path = $2 ORDER BY created_at DESC LIMIT 1`,
            [website.id, filePath]
          );
          if (hashResult.rows.length > 0) fileHash = hashResult.rows[0].file_hash;
        }
        if (!fileHash) {
          logger.warn({
            message: 'No file_hash found for file_path in batch delete',
            filePath,
            websiteId: website.id
          }, {
            component: 'scan-controller',
            event: 'batch_delete_missing_hash'
          });
          continue;
        }
        // Get all detections for this file
        const detectionResult = await pool.query(
          `SELECT * FROM scan_detections WHERE website_id = $1 AND file_path = $2 AND file_hash = $3`,
          [website.id, filePath, fileHash]
        );
        // Mark all as deleted
        await pool.query(
          `UPDATE scan_detections SET status = 'deleted' WHERE website_id = $1 AND file_path = $2 AND file_hash = $3`,
          [website.id, filePath, fileHash]
        );
        // Insert into deleted_detections for each
        for (const detection of detectionResult.rows) {
          await pool.query(
            `INSERT INTO deleted_detections (scan_detection_id, file_path, timestamp, confidence, threat_score) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`,
            [detection.id, filePath, new Date(), detection.confidence || 0, detection.threat_score || 0]
          );
        }
        logger.info({
          message: 'Batch: Marked all past detections as deleted and created deleted_detections records',
          websiteId: website.id,
          filePath,
          fileHash
        }, {
          component: 'scan-controller',
          event: 'batch_delete_bulk_update'
        });
      }
    }

    // If operation is quarantine, update database records for each successfully quarantined file
    if (operation === 'quarantine' && result.status === 'success') {
      // Process each successful result
      for (let i = 0; i < result.results.success.length; i++) {
        const successItem = result.results.success[i];
        const filePath = successItem.file_path;
        const quarantineResult = successItem.result;
        
        // Track the final detection ID we'll use
        let foundScanDetectionId = null;
        
        // If we have scan_detection_ids array, use the corresponding ID
        const scanDetectionId = scan_detection_ids && scan_detection_ids[i] ? scan_detection_ids[i] : null;
        
        if (scanDetectionId) {
          try {
            // Update scan detection status to quarantined
            const detectionId = typeof scanDetectionId === 'string'
              ? parseInt(scanDetectionId, 10)
              : scanDetectionId;
            logger.debug({
              message: 'Marking scan detection as quarantined',
              scanDetectionId: detectionId
            }, {
              component: 'scan-controller',
              event: 'pre_update_detection_status'
            });
            const updated = await updateScanDetectionStatus(detectionId, 'quarantined');
            foundScanDetectionId = detectionId;
            logger.debug({
              message: 'Updated scan detection status',
              scanDetectionId: updated.id ?? detectionId,
              status: updated.status
            }, {
              component: 'scan-controller',
              event: 'update_detection_status'
            });
          } catch (dbError) {
            // Ensure dbError is always an Error object
            const err = dbError instanceof Error ? dbError : new Error(String(dbError) || 'Unknown error');
            logger.error({
              message: 'Failed to update scan detection status in batch operation',
              error: err, 
              scanDetectionId: scanDetectionId
            }, {
              component: 'scan-controller',
              event: 'batch_update_detection_status_error'
            });
          }
        }
        
        // If we don't have a scan_detection_id or the update failed, try to find it by file path
        if (!foundScanDetectionId) {
          try {
            // First try to find the detection ID directly
            const findDetectionQuery = `
              SELECT id, scan_id FROM scan_detections 
              WHERE file_path = $1 AND website_id = $2
              ORDER BY created_at DESC LIMIT 1
            `;
            
            const detectionResult = await pool.query(findDetectionQuery, [filePath, website.id]);
            
            if (detectionResult.rows.length > 0) {
              foundScanDetectionId = detectionResult.rows[0].id;
              const scanId = detectionResult.rows[0].scan_id;
              
              logger.debug({
                message: 'Found scan_detection_id for file path in batch operation',
                scanDetectionId: foundScanDetectionId,
                scanId,
                filePath
              }, {
                component: 'scan-controller',
                event: 'batch_found_scan_detection_id'
              });
              
              // Update the scan detection status
              const updated = await updateScanDetectionStatus(foundScanDetectionId, 'quarantined');
              
              logger.debug({
                message: 'Updated scan detection status by found ID in batch operation',
                scanDetectionId: foundScanDetectionId,
                status: 'quarantined'
              }, {
                component: 'scan-controller',
                event: 'batch_update_detection_status'
              });
            } else {
              // If we can't find the detection ID, try updating by path
              const findScanQuery = `
                SELECT scan_id FROM scan_detections 
                WHERE file_path = $1 
                ORDER BY created_at DESC LIMIT 1
              `;
              
              const scanResult = await pool.query(findScanQuery, [filePath]);
              
              if (scanResult.rows.length > 0) {
                const scanId = scanResult.rows[0].scan_id;
                
                logger.debug({
                  message: 'Found scan_id for file path in batch operation',
                  scanId,
                  filePath
                }, {
                  component: 'scan-controller',
                  event: 'batch_found_scan_id'
                });
                
                const pathUpdate = await updateScanDetectionByPath(scanId, filePath, 'quarantined');
                
                // Try to get the detection ID from the updated rows
                if (pathUpdate.updatedRows && pathUpdate.updatedRows.length > 0) {
                  foundScanDetectionId = pathUpdate.updatedRows[0].id;
                }
                
                logger.debug({
                  message: 'Updated scan detection status by path in batch operation',
                  scanId,
                  filePath,
                  status: 'quarantined',
                  rowsAffected: pathUpdate.rowsAffected,
                  foundScanDetectionId
                }, {
                  component: 'scan-controller',
                  event: 'batch_update_detection_status_by_path'
                });
              } else {
                logger.warn({
                  message: 'No scan_id or scan_detection_id found for file path in batch operation',
                  filePath,
                  websiteId: website.id
                }, {
                  component: 'scan-controller',
                  event: 'batch_missing_scan_detection_id'
                });
              }
            }
          } catch (dbError) {
            // Ensure dbError is always an Error object
            const err = dbError instanceof Error ? dbError : new Error(String(dbError) || 'Unknown error');
            logger.error({
              message: 'Failed to find or update scan detection in batch operation',
              error: err,
              filePath
            }, {
              component: 'scan-controller',
              event: 'batch_find_detection_error'
            });
          }
        }

        // Create quarantined detection record if we have a valid quarantine result
        if (quarantineResult && typeof quarantineResult !== 'boolean' && quarantineResult.quarantine_id) {
          try {
            // Use foundScanDetectionId if available, otherwise fall back to scanDetectionId
            const detectionId = foundScanDetectionId || (scanDetectionId ? parseInt(scanDetectionId) : null);
            
            await createQuarantinedDetection({
              scan_detection_id: detectionId,
              quarantine_id: quarantineResult.quarantine_id,
              original_path: filePath,
              quarantine_path: quarantineResult.quarantine_path || 'unknown',
              timestamp: new Date(),
              scan_finding_id: successItem.scan_finding_id || null,
              file_size: quarantineResult.file_size || 0,
              file_type: quarantineResult.file_type || 'unknown',
              file_hash: quarantineResult.file_hash || null,
              detection_type: quarantineResult.detection_type ? (Array.isArray(quarantineResult.detection_type) ? quarantineResult.detection_type : [quarantineResult.detection_type]) : ['batch']
            });

            logger.debug({
              message: 'Created quarantined detection record in batch operation',
              quarantineId: quarantineResult.quarantine_id,
              filePath,
              scanDetectionId: detectionId
            }, {
              component: 'scan-controller',
              event: 'batch_create_quarantined_detection'
            });
          } catch (dbError) {
            // Ensure dbError is always an Error object
            const err = dbError instanceof Error ? dbError : new Error(String(dbError) || 'Unknown error');
            logger.error({
              message: 'Failed to create quarantined detection record in batch operation',
              error: err, 
              quarantineId: quarantineResult.quarantine_id,
              filePath
            }, {
              component: 'scan-controller',
              event: 'batch_create_quarantined_detection_error'
            });
          }
        }
      }
    }
    
    // If operation is delete, handle moving records from quarantined_detections to deleted_detections
    if (operation === 'delete' && result.status === 'success' && quarantine_ids && Array.isArray(quarantine_ids)) {
      // Process each quarantine ID
      for (let i = 0; i < quarantine_ids.length; i++) {
        const quarantineId = quarantine_ids[i];
        if (!quarantineId) continue;
        
        try {
          // Move the quarantined detection to deleted_detections
          const moveResult = await moveQuarantinedToDeleted(quarantineId);
          
          logger.debug({
            message: 'Moved quarantined file to deleted in batch operation',
            quarantineId,
            deletedDetectionId: moveResult.deletedDetectionId,
            scanDetectionId: moveResult.scanDetectionId,
            filePath: moveResult.filePath
          }, {
            component: 'scan-controller',
            event: 'batch_move_quarantined_to_deleted'
          });
        } catch (dbError) {
          // Ensure dbError is always an Error object
          const err = dbError instanceof Error ? dbError : new Error(String(dbError) || 'Unknown error');
          logger.error({
            message: 'Failed to move quarantined file to deleted in batch operation',
            error: err,
            quarantineId
          }, {
            component: 'scan-controller',
            event: 'batch_move_quarantined_to_deleted_error'
          });
        }
      }
    } else if (operation === 'delete' && result.status === 'success' && scan_detection_ids && Array.isArray(scan_detection_ids)) {
      // For regular (non-quarantined) files, update scan detection status and create deleted detection records
      for (let i = 0; i < scan_detection_ids.length; i++) {
        const scanDetectionId = scan_detection_ids[i];
        if (!scanDetectionId) continue;
        
        try {
          // First, get the file_path and file_hash for this detection
          const detectionId = typeof scanDetectionId === 'string'
            ? parseInt(scanDetectionId, 10)
            : scanDetectionId;
          
          // Get the detection details
          const detectionQuery = `
            SELECT * FROM scan_detections WHERE id = $1
          `;
          const detectionResult = await pool.query(detectionQuery, [detectionId]);
          
          if (detectionResult.rows.length === 0) {
            logger.warn({
              message: 'Scan detection not found for batch delete operation',
              scanDetectionId: detectionId
            }, {
              component: 'scan-controller',
              event: 'batch_delete_detection_not_found'
            });
            continue;
          }
          
          const detection = detectionResult.rows[0];
          const filePath = detection.file_path;
          const fileHash = detection.file_hash;
          const websiteId = detection.website_id;
          
          if (!filePath || !fileHash || !websiteId) {
            logger.warn({
              message: 'Missing required fields for batch delete operation',
              scanDetectionId: detectionId,
              filePath,
              fileHash,
              websiteId
            }, {
              component: 'scan-controller',
              event: 'batch_delete_missing_fields'
            });
            continue;
          }
          
          // Mark all detections with the same file_path and file_hash as deleted
          logger.debug({
            message: 'Marking all matching scan detections as deleted',
            websiteId,
            filePath,
            fileHash
          }, {
            component: 'scan-controller',
            event: 'batch_delete_mark_all'
          });
          
          // Update all matching scan_detections to 'deleted'
          const updateQuery = `
            UPDATE scan_detections 
            SET status = 'deleted' 
            WHERE website_id = $1 AND file_path = $2 AND file_hash = $3
          `;
          await pool.query(updateQuery, [websiteId, filePath, fileHash]);
          
          // Find the latest detection to use for the deleted_detections entry
          const latestDetectionQuery = `
            SELECT * FROM scan_detections 
            WHERE website_id = $1 AND file_path = $2 AND file_hash = $3
            ORDER BY created_at DESC LIMIT 1
          `;
          const latestResult = await pool.query(latestDetectionQuery, [websiteId, filePath, fileHash]);
          
          if (latestResult.rows.length > 0) {
            const latestDetection = latestResult.rows[0];
            
            // Create a record in deleted_detections for the latest detection
            const insertQuery = `
              INSERT INTO deleted_detections (
                scan_detection_id, file_path, timestamp, confidence, threat_score
              ) VALUES ($1, $2, $3, $4, $5)
              RETURNING id
            `;
            
            const insertValues = [
              latestDetection.id,
              filePath,
              new Date(),
              latestDetection.confidence || 0,
              latestDetection.threat_score || 0
            ];
            
            const insertResult = await pool.query(insertQuery, insertValues);
            
            logger.debug({
              message: 'Created deleted detection record for latest detection',
              scanDetectionId: latestDetection.id,
              filePath,
              fileHash,
              deletedDetectionId: insertResult.rows[0].id
            }, {
              component: 'scan-controller',
              event: 'batch_create_deleted_detection'
            });
          }
        } catch (dbError) {
          // Ensure dbError is always an Error object
          const err = dbError instanceof Error ? dbError : new Error(String(dbError) || 'Unknown error');
          logger.error({
            message: 'Failed to update scan detections or create deleted detection in batch operation',
            error: err,
            scanDetectionId
          }, {
            component: 'scan-controller',
            event: 'batch_update_detection_status_error'
          });
        }
      }
    }

    logger.info({
      message: `Batch ${operation} operation completed`,
      domain,
      successCount: result.results.success.length,
      failedCount: result.results.failed.length,
      totalCount: result.results.total
    }, {
      component: 'scan-controller',
      event: 'batch_operation_completed'
    });

    res.json(result);
  } catch (error) {
    console.error('Error processing batch operation:', error);
    // Ensure error is always an Error object
    const err = error instanceof Error ? error : new Error(String(error) || 'Unknown error');
    logger.error({
      message: 'Error processing batch operation',
      error: err, 
      domain: req.params.domain,
      operation: req.body.operation
    }, {
      component: 'scan-controller',
      event: 'batch_operation_error'
    });
    res.status(500).json({ error: err.message });
  }
});

// Delete a single file
router.post('/:domain/delete', async (req, res) => {
  try {
    const { domain } = req.params;
    const { file_path, scan_detection_id, quarantine_id } = req.body;

    if (!file_path) {
      return res.status(400).json({ error: 'file_path is required' });
    }

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Delete file
    logger.debug({
      message: 'Deleting file',
      domain,
      filePath: file_path,
      scanDetectionId: scan_detection_id,
      quarantineId: quarantine_id
    }, {
      component: 'scan-controller',
      event: 'delete_file'
    });

    // Check if the file is quarantined
    if (quarantine_id) {
      try {
        // Move the file from quarantined_detections to deleted_detections
        const moveResult = await moveQuarantinedToDeleted(quarantine_id);
        
        logger.debug({
          message: 'Moved quarantined file to deleted',
          quarantineId: quarantine_id,
          deletedDetectionId: moveResult.deletedDetectionId,
          scanDetectionId: moveResult.scanDetectionId,
          filePath: moveResult.filePath
        }, {
          component: 'scan-controller',
          event: 'move_quarantined_to_deleted'
        });

        // Still call the WPSec API to ensure the file is actually deleted
        const result = await api.deleteFile(file_path);

        logger.info({
          message: 'Quarantined file deleted successfully',
          domain,
          filePath: file_path,
          quarantineId: quarantine_id,
          scanDetectionId: scan_detection_id
        }, {
          component: 'scan-controller',
          event: 'quarantined_file_deleted'
        });

        res.json({
          message: 'Quarantined file deleted successfully',
          deleted_from_quarantine: true,
          ...result
        });
      } catch (dbError) {
        // Ensure dbError is always an Error object
        const err = dbError instanceof Error ? dbError : new Error(String(dbError) || 'Unknown error');
        logger.error({
          message: 'Failed to move quarantined file to deleted',
          error: err,
          quarantineId: quarantine_id,
          filePath: file_path
        }, {
          component: 'scan-controller',
          event: 'move_quarantined_to_deleted_error'
        });

        // Continue with the delete operation even if the database update fails
        const result = await api.deleteFile(file_path);
        res.json(result);
      }
    } else {
      // Regular file delete (not quarantined)
      const result = await api.deleteFile(file_path);

      // Enhanced logic: mark all past detections of this file as deleted and insert into deleted_detections
      // Fetch file_hash for this file_path and website
      let fileHash = req.body.file_hash;
      if (!fileHash) {
        // Try to get the latest file_hash from scan_detections
        const hashResult = await pool.query(
          `SELECT file_hash FROM scan_detections WHERE website_id = $1 AND file_path = $2 ORDER BY created_at DESC LIMIT 1`,
          [website.id, file_path]
        );
        if (hashResult.rows.length > 0) fileHash = hashResult.rows[0].file_hash;
      }
      if (!fileHash) {
        logger.warn({
          message: 'No file_hash found for file_path when deleting',
          filePath: file_path,
          websiteId: website.id
        }, {
          component: 'scan-controller',
          event: 'delete_file_missing_hash'
        });
        // Fallback: do not bulk update, just proceed as before
      }
      if (fileHash) {
        // Get all detections for this file
        const detectionResult = await pool.query(
          `SELECT * FROM scan_detections WHERE website_id = $1 AND file_path = $2 AND file_hash = $3`,
          [website.id, file_path, fileHash]
        );
        // Mark all as deleted
        await pool.query(
          `UPDATE scan_detections SET status = 'deleted' WHERE website_id = $1 AND file_path = $2 AND file_hash = $3`,
          [website.id, file_path, fileHash]
        );
        // Insert into deleted_detections for each
        for (const detection of detectionResult.rows) {
          await pool.query(
            `INSERT INTO deleted_detections (scan_detection_id, file_path, timestamp, confidence, threat_score) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`,
            [detection.id, file_path, new Date(), detection.confidence || 0, detection.threat_score || 0]
          );
        }
        logger.info({
          message: 'Marked all past detections as deleted and created deleted_detections records',
          websiteId: website.id,
          filePath: file_path,
          fileHash
        }, {
          component: 'scan-controller',
          event: 'delete_file_bulk_update'
        });
      } else if (scan_detection_id) {
        // Fallback: update just the single detection
        try {
          const detectionId = typeof scan_detection_id === 'string'
            ? parseInt(scan_detection_id, 10)
            : scan_detection_id;
          logger.debug({
            message: 'Marking scan detection as deleted',
            scanDetectionId: detectionId
          }, {
            component: 'scan-controller',
            event: 'pre_update_detection_status'
          });
          const updated = await updateScanDetectionStatus(detectionId, 'deleted');
          logger.debug({
            message: 'Updated scan detection status',
            scanDetectionId: updated.id ?? detectionId,
            status: updated.status
          }, {
            component: 'scan-controller',
            event: 'update_detection_status'
          });
          // Create a record in deleted_detections
          const insertQuery = `
            INSERT INTO deleted_detections (
              scan_detection_id, file_path, timestamp, confidence, threat_score
            ) VALUES ($1, $2, $3, $4, $5)
            RETURNING id
          `;
          // Fetch confidence/threat_score from scan_detections if not defined
          let conf: number | undefined = undefined;
          let ts: number | undefined = undefined;
          if (conf === undefined || ts === undefined) {
            const detectionRes = await pool.query(
              `SELECT confidence, threat_score FROM scan_detections WHERE id = $1`,
              [scan_detection_id]
            );
            if (detectionRes.rows.length > 0) {
              conf = detectionRes.rows[0].confidence || 0;
              ts = detectionRes.rows[0].threat_score || 0;
            } else {
              conf = 0;
              ts = 0;
            }
          }
          const insertValues = [scan_detection_id, file_path, new Date(), conf, ts];
          const insertResult = await pool.query(insertQuery, insertValues);
          logger.debug({
            message: 'Created deleted detection record',
            scanDetectionId: scan_detection_id,
            filePath: file_path,
            deletedDetectionId: insertResult.rows[0].id
          }, {
            component: 'scan-controller',
            event: 'create_deleted_detection'
          });
        } catch (dbError) {
          // Ensure dbError is always an Error object
          const err = dbError instanceof Error ? dbError : new Error(String(dbError) || 'Unknown error');
          logger.error({
            message: 'Failed to update scan detection status or create deleted detection',
            error: err,
            scanDetectionId: scan_detection_id,
            filePath: file_path
          }, {
            component: 'scan-controller',
            event: 'update_detection_status_error'
          });
        }
      }

      logger.info({
        message: 'File deleted successfully',
        domain,
        filePath: file_path,
        scanDetectionId: scan_detection_id
      }, {
        component: 'scan-controller',
        event: 'file_deleted'
      });

      res.json(result);
    }
  } catch (error) {
    console.error('Error deleting file:', error);
    // Ensure error is always an Error object
    const err = error instanceof Error ? error : new Error(String(error) || 'Unknown error');
    logger.error({
      message: 'Error deleting file',
      error: err,
      domain: req.params.domain,
      filePath: req.body.file_path,
      scanDetectionId: req.body.scan_detection_id,
      quarantineId: req.body.quarantine_id
    }, {
      component: 'scan-controller',
      event: 'delete_file_error'
    });
    res.status(500).json({ error: err.message });
  }
});

// Get all scan detections for a domain
router.get('/:domain/detections', async (req, res) => {
  try {
    const { domain } = req.params;
    const status = req.query.status as string | undefined;
    const scan_id = req.query.scan_id as string | undefined;
    
    // Parse and validate limit/offset
    let limit = 100;
    let offset = 0;
    
    if (req.query.limit) {
      const parsedLimit = parseInt(req.query.limit as string);
      if (!isNaN(parsedLimit) && parsedLimit > 0) {
        limit = parsedLimit;
      }
    }
    
    if (req.query.offset) {
      const parsedOffset = parseInt(req.query.offset as string);
      if (!isNaN(parsedOffset) && parsedOffset >= 0) {
        offset = parsedOffset;
      }
    }
    
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }
    
    // Get the latest scan ID for this website if not provided
    let latestScanId = scan_id;
    if (!latestScanId) {
      const latestScanQuery = `
        SELECT scan_id FROM website_scans
        WHERE website_id = $1
        ORDER BY started_at DESC
        LIMIT 1
      `;
      const latestScanResult = await pool.query(latestScanQuery, [website.id]);
      if (latestScanResult.rows.length > 0) {
        latestScanId = latestScanResult.rows[0].scan_id;
      }
    }
    
    logger.debug({
      message: 'Retrieving scan detections',
      domain,
      websiteId: website.id,
      status: status || 'all',
      limit,
      offset,
      latestScanId,
      threatScoreFilter: 'above 4'
    }, {
      component: 'scan-controller',
      event: 'get_scan_detections'
    });
    
    // Parameters for the query
    const queryParams = [website.id.toString()];
    if (latestScanId) {
      queryParams.push(latestScanId);
    }
    if (status) {
      queryParams.push(status);
    }
    
    // Add pagination parameters
    queryParams.push(limit.toString(), offset.toString());
    
    // Build the query to get:
    // 1. Active detections from the latest scan only
    // 2. Quarantined or deleted items from any scan
    const dataQuery = `
      WITH latest_scan_detections AS (
        SELECT DISTINCT ON (sd.file_hash, sd.file_path) 
          sd.id,
          sd.website_id,
          sd.scan_id,
          sd.file_path,
          sd.threat_score,
          sd.confidence,
          sd.detection_type,
          sd.severity,
          sd.description,
          sd.file_hash,
          sd.file_size,
          sd.context_type,
          sd.risk_level,
          sd.version_number,
          sd.created_at,
          sd.status,
          ws.scan_id as website_scan_id,
          ws.started_at as scan_started_at,
          ws.completed_at as scan_completed_at,
          ws.status as scan_status,
          NULL::json as quarantine_info,
          NULL::json as deletion_info
        FROM scan_detections sd
        LEFT JOIN website_scans ws ON sd.scan_id = ws.scan_id
        WHERE sd.website_id = $1
          AND sd.threat_score > 4
          ${latestScanId ? 'AND sd.scan_id = $2' : ''}
          ${status ? `AND sd.status = $${latestScanId ? '3' : '2'}` : 'AND sd.status = \'active\''}
          AND NOT EXISTS (
            SELECT 1 FROM quarantined_detections qd WHERE qd.scan_detection_id = sd.id
          )
          AND NOT EXISTS (
            SELECT 1 FROM deleted_detections dd WHERE dd.scan_detection_id = sd.id
          )
        ORDER BY sd.file_hash, sd.file_path, sd.created_at DESC
      ),
      special_items AS (
        SELECT DISTINCT ON (sd.file_hash, sd.file_path) 
          sd.id,
          sd.website_id,
          sd.scan_id,
          sd.file_path,
          sd.threat_score,
          sd.confidence,
          sd.detection_type,
          sd.severity,
          sd.description,
          sd.file_hash,
          sd.file_size,
          sd.context_type,
          sd.risk_level,
          sd.version_number,
          sd.created_at,
          sd.status,
          ws.scan_id as website_scan_id,
          ws.started_at as scan_started_at,
          ws.completed_at as scan_completed_at,
          ws.status as scan_status,
          CASE 
            WHEN qd.id IS NOT NULL THEN json_build_object(
              'id', qd.id,
              'quarantine_id', qd.quarantine_id,
              'original_path', qd.original_path,
              'quarantine_path', qd.quarantine_path,
              'timestamp', qd.timestamp,
              'file_size', qd.file_size,
              'file_type', qd.file_type,
              'file_hash', qd.file_hash
            )
            ELSE NULL
          END as quarantine_info,
          CASE 
            WHEN dd.id IS NOT NULL THEN json_build_object(
              'id', dd.id,
              'timestamp', dd.timestamp
            )
            ELSE NULL
          END as deletion_info
        FROM scan_detections sd
        LEFT JOIN website_scans ws ON sd.scan_id = ws.scan_id
        LEFT JOIN quarantined_detections qd ON sd.id = qd.scan_detection_id
        LEFT JOIN deleted_detections dd ON sd.id = dd.scan_detection_id
        WHERE sd.website_id = $1
          AND sd.threat_score > 4
          ${status ? `AND sd.status = $${latestScanId ? '3' : '2'}` : ''}
          AND (qd.id IS NOT NULL OR dd.id IS NOT NULL)
        ORDER BY sd.file_hash, sd.file_path, sd.created_at DESC
      )
      SELECT * FROM (
        SELECT * FROM latest_scan_detections
        UNION ALL
        SELECT * FROM special_items
      ) combined_results
      ORDER BY file_hash, file_path, created_at DESC
      LIMIT $${latestScanId ? (status ? '4' : '3') : (status ? '3' : '2')} 
      OFFSET $${latestScanId ? (status ? '5' : '4') : (status ? '4' : '3')}
    `;
    
    // Log the query and parameters for debugging
    console.log('EXECUTING QUERY:', dataQuery);
    console.log('WITH PARAMETERS:', queryParams);
    
    // Execute data query
    const result = await pool.query(dataQuery, queryParams);
    
    // Count query for pagination
    const countQuery = `
      SELECT COUNT(*) FROM (
        SELECT DISTINCT ON (sd.file_hash, sd.file_path) sd.id
        FROM scan_detections sd
        LEFT JOIN quarantined_detections qd ON sd.id = qd.scan_detection_id
        LEFT JOIN deleted_detections dd ON sd.id = dd.scan_detection_id
        WHERE sd.website_id = $1
          AND sd.threat_score > 4
          ${latestScanId ? 'AND (sd.scan_id = $2 OR qd.id IS NOT NULL OR dd.id IS NOT NULL)' : ''}
          ${status ? `AND sd.status = $${latestScanId ? '3' : '2'}` : ''}
      ) as count_query
    `;
    
    const countParams = [website.id.toString()];
    if (latestScanId) {
      countParams.push(latestScanId);
    }
    if (status) {
      countParams.push(status);
    }
    
    const countResult = await pool.query(countQuery, countParams);
    const totalCount = parseInt(countResult.rows[0].count);
    
    logger.debug({
      message: 'Retrieved scan detections',
      domain,
      count: result.rows.length,
      totalCount
    }, {
      component: 'scan-controller',
      event: 'scan_detections_retrieved'
    });
    
    // Ensure detection_type is always an array of strings
    const detections = result.rows.map((row: any) => {
      // If detection_type is null, undefined, or not an array, normalize it
      if (!Array.isArray(row.detection_type)) {
        if (typeof row.detection_type === 'string' && row.detection_type.length > 0) {
          row.detection_type = [row.detection_type];
        } else {
          row.detection_type = [];
        }
      }
      return row;
    });

    // Create the response object
    const responseObj = {
      status: 'success',
      detections,
      pagination: {
        total: totalCount,
        limit,
        offset,
        has_more: totalCount > (offset + detections.length)
      }
    };
    
    // Log the full response for debugging
    console.log('FULL DETECTION RESPONSE:', JSON.stringify(responseObj, null, 2));
    
    res.json(responseObj);
  } catch (error) {
    const err = error instanceof Error ? error : new Error(String(error) || 'Unknown error');
    logger.error({
      message: 'Error getting scan detections',
      error: err,
      domain: req.params.domain
    }, {
      component: 'scan-controller',
      event: 'get_scan_detections_error'
    });
    res.status(500).json({ error: err.message });
  }
});

export default router;
