import { Router } from 'express';
import { WPSecAPI } from '../services/wpsec';
import { ScanStore } from '../services/scan-store';
import type { ScanStartResponse, ScanStatus, ScanResults, QuarantineResponse, QuarantineListResponse, QuarantineRestoreResponse, BatchOperationResponse } from '../types/wpsec';
import { getWebsiteByDomain, createWebsiteScanResult, updateScanDetectionStatus, createQuarantinedDetection, removeQuarantinedDetection, moveQuarantinedToDeleted, default as pool } from '../config/db';
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
    // Capture update status
    let detectionUpdate: any = null;

    // Update the detection status in the database if scan_detection_id is provided
    if (scan_detection_id) {
      // Ensure numeric ID and log before updating
      const detectionId = typeof scan_detection_id === 'string'
        ? parseInt(scan_detection_id, 10)
        : scan_detection_id;
      logger.debug({
        message: 'Marking scan detection as quarantined',
        scanDetectionId: detectionId
      }, {
        component: 'scan-controller',
        event: 'pre_update_detection_status'
      });
      try {
        const updated = await updateScanDetectionStatus(detectionId, 'quarantined');
        detectionUpdate = updated;
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
          message: 'Failed to update scan detection status',
          error: err, 
          scanDetectionId: detectionId
        }, {
          component: 'scan-controller',
          event: 'update_detection_status_error'
        });
      }
    }

    // Insert the file into the quarantined_detections table
    try {
      await createQuarantinedDetection({
        scan_detection_id: scan_detection_id ? parseInt(scan_detection_id) : null,
        quarantine_id: result.quarantine_id,
        original_path: file_path,
        quarantine_path: result.quarantine_path || 'unknown',
        timestamp: new Date(),
        scan_finding_id: scan_finding_id || null,
        file_size: result.file_size || 0,
        file_type: result.file_type || 'unknown',
        file_hash: result.file_hash || null,
        detection_type: result.detection_type || 'manual'
      });

      logger.debug({
        message: 'Created quarantined detection record',
        quarantineId: result.quarantine_id,
        filePath: file_path
      }, {
        component: 'scan-controller',
        event: 'create_quarantined_detection'
      });
    } catch (dbError) {
      // Ensure dbError is always an Error object
      const err = dbError instanceof Error ? dbError : new Error(String(dbError) || 'Unknown error');
      logger.error({
        message: 'Failed to create quarantined detection record',
        error: err, 
        quarantineId: result.quarantine_id,
        filePath: file_path
      }, {
        component: 'scan-controller',
        event: 'create_quarantined_detection_error'
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

    res.json({ result, detectionUpdate });
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

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Get quarantined files
    const files = await api.getQuarantinedFiles();
    res.json(files);
  } catch (error) {
    console.error('Error getting quarantined files:', error);
    const err = error instanceof Error ? error : new Error('Unknown error');
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

    // Remove quarantined detection records
    for (const id of ids) {
      try {
        const { deletedRecord, scanDetectionId } = await removeQuarantinedDetection(id);
        // Update the scan detection status back to 'active'
        if (scanDetectionId) {
          try {
            await updateScanDetectionStatus(scanDetectionId, 'active');
            logger.debug({
              message: 'Updated scan detection status',
              scanDetectionId,
              status: 'active'
            }, {
              component: 'scan-controller',
              event: 'update_detection_status'
            });
          } catch (dbError) {
            const err = dbError instanceof Error ? dbError : new Error(String(dbError) || 'Unknown error');
            logger.error({
              message: 'Failed to update scan detection status',
              error: err,
              scanDetectionId
            }, {
              component: 'scan-controller',
              event: 'update_detection_status_error'
            });
          }
        }
        logger.debug({
          message: 'Removed quarantined detection record',
          quarantineId: id,
          originalPath: deletedRecord.original_path
        }, {
          component: 'scan-controller',
          event: 'remove_quarantined_detection'
        });
      } catch (dbError) {
        const err = dbError instanceof Error ? dbError : new Error(String(dbError) || 'Unknown error');
        logger.error({
          message: 'Failed to remove quarantined detection record',
          error: err,
          quarantineId: id
        }, {
          component: 'scan-controller',
          event: 'remove_quarantined_detection_error'
        });
      }
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

    // If operation is quarantine, update database records for each successfully quarantined file
    if (operation === 'quarantine' && result.status === 'success') {
      // Process each successful result
      for (let i = 0; i < result.results.success.length; i++) {
        const successItem = result.results.success[i];
        const filePath = successItem.file_path;
        const quarantineResult = successItem.result;
        
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

        // Create quarantined detection record if we have a valid quarantine result
        if (quarantineResult && typeof quarantineResult !== 'boolean' && quarantineResult.quarantine_id) {
          try {
            await createQuarantinedDetection({
              scan_detection_id: scanDetectionId ? parseInt(scanDetectionId) : null,
              quarantine_id: quarantineResult.quarantine_id,
              original_path: filePath,
              quarantine_path: quarantineResult.quarantine_path || 'unknown',
              timestamp: new Date(),
              scan_finding_id: successItem.scan_finding_id || null,
              file_size: quarantineResult.file_size || 0,
              file_type: quarantineResult.file_type || 'unknown',
              file_hash: quarantineResult.file_hash || null,
              detection_type: quarantineResult.detection_type || 'batch'
            });

            logger.debug({
              message: 'Created quarantined detection record in batch operation',
              quarantineId: quarantineResult.quarantine_id,
              filePath
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
          // Update scan detection status to deleted
          const detectionId = typeof scanDetectionId === 'string'
            ? parseInt(scanDetectionId, 10)
            : scanDetectionId;
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
          const filePath = files[i]?.file_path;
          if (filePath) {
            const insertQuery = `
              INSERT INTO deleted_detections (
                scan_detection_id, file_path, timestamp
              ) VALUES ($1, $2, $3)
              RETURNING id
            `;
            
            const insertValues = [
              scanDetectionId,
              filePath,
              new Date()
            ];
            
            const insertResult = await pool.query(insertQuery, insertValues);
            
            logger.debug({
              message: 'Created deleted detection record in batch operation',
              scanDetectionId,
              filePath,
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
            message: 'Failed to update scan detection status or create deleted detection in batch operation',
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

      // If we have a scan_detection_id, update its status to 'deleted'
      if (scan_detection_id) {
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
              scan_detection_id, file_path, timestamp
            ) VALUES ($1, $2, $3)
            RETURNING id
          `;
          
          const insertValues = [
            scan_detection_id,
            file_path,
            new Date()
          ];
          
          const insertResult = await pool.query(insertQuery, insertValues);
          
          logger.debug({
            message: 'Created deleted detection record',
            scanDetectionId,
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

export default router;
