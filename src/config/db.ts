import { Pool } from 'pg';
import { config } from 'dotenv';
import { logger } from '../services/logger';

// Load environment variables
config({ path: '.env.local' });

if (!process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL environment variable is not set');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// Log database connection events
pool.on('connect', () => {
  logger.info({
    message: 'New database connection established'
  }, {
    component: 'database',
    event: 'connection_established'
  });
});

pool.on('error', (err) => {
  logger.error({
    message: 'Database connection error',
    error: err
  }, {
    component: 'database',
    event: 'connection_error'
  });
});

pool.on('remove', () => {
  logger.debug({
    message: 'Database connection removed from pool'
  }, {
    component: 'database',
    event: 'connection_removed'
  });
});

export interface Website {
  id: number;
  domain: string;
  user_id: number;
  created_at: Date;
  updated_at: Date;
}

export async function getWebsiteByDomain(domain: string): Promise<Website | null> {
  logger.debug({
    message: 'Looking up website by domain',
    domain
  }, {
    component: 'database',
    event: 'website_lookup'
  });

  try {
    const result = await pool.query<Website>(
      'SELECT * FROM websites WHERE domain = $1',
      [domain]
    );

    const website = result.rows[0] || null;
    logger.debug({
      message: website ? 'Website found' : 'Website not found',
      domain,
      found: !!website
    }, {
      component: 'database',
      event: 'website_lookup_result'
    });

    return website;
  } catch (error: any) {
    logger.error({
      message: 'Error looking up website',
      error,
      domain
    }, {
      component: 'database',
      event: 'website_lookup_error'
    });
    throw error;
  }
}

export async function createWebsiteScanResult(websiteId: string | number, scanData: {
  scan_id: string;
  infected_files: number;
  total_files: number;
  started_at: Date;
  completed_at: Date;
  duration: number;
  status?: 'pending' | 'completed' | 'failed';
  error_message?: string;
}) {
  try {
    logger.debug({
      message: 'Creating website scan result',
      websiteId,
      scanId: scanData.scan_id,
      status: scanData.status
    }, {
      component: 'database',
      event: 'create_scan_result'
    });

    await pool.query(
      `INSERT INTO website_scans (
        website_id, scan_id, infected_files_count, total_files_count,
        started_at, completed_at, duration_seconds, status, error_message
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        websiteId,
        scanData.scan_id,
        scanData.infected_files,
        scanData.total_files,
        scanData.started_at,
        scanData.completed_at,
        scanData.duration,
        scanData.status || 'completed',
        scanData.error_message
      ]
    );

    logger.info({
      message: 'Website scan result created',
      websiteId,
      scanId: scanData.scan_id,
      status: scanData.status || 'completed'
    }, {
      component: 'database',
      event: 'scan_result_created'
    });
  } catch (error: any) {
    logger.error({
      message: 'Error creating website scan result',
      error,
      websiteId,
      scanId: scanData.scan_id
    }, {
      component: 'database',
      event: 'scan_result_error'
    });
    throw error;
  }
}

export async function createScanDetection(websiteId: string | number, scanId: string, detection: {
  file_path: string;
  threat_score: number;
  confidence: number;
  detection_type: string;
  severity: string;
  description: string;
  file_hash?: string;
  file_size: number;
  context_type: string;
  risk_level: string;
}) {
  try {
    // Convert websiteId to string if it's a number
    const websiteIdStr = typeof websiteId === 'number' ? String(websiteId) : websiteId;
    
    // Use the new versioning logic to handle scan detections
    const result = await handleScanDetectionVersioning(
      detection.file_path,
      websiteIdStr,
      scanId,
      {
        threatScore: detection.threat_score,
        confidence: detection.confidence,
        detectionType: detection.detection_type,
        severity: detection.severity,
        description: detection.description,
        fileHash: detection.file_hash,
        fileSize: detection.file_size,
        contextType: detection.context_type,
        riskLevel: detection.risk_level
      }
    );
    
    // Log reinfection events (when version > 1 and it's a new detection)
    if (result.isNew && result.versionNumber > 1) {
      logger.warn({
        message: 'Reinfection detected',
        filePath: detection.file_path,
        versionNumber: result.versionNumber,
        scanId,
        websiteId: websiteIdStr
      }, {
        component: 'database',
        event: 'reinfection_detected'
      });
    }
    
    return { id: result.scanDetectionId };
  } catch (error) {
    // Ensure error is always an Error object
    const err = error instanceof Error ? error : new Error(String(error) || 'Unknown error');
    logger.error({
      message: 'Error creating scan detection',
      error: err, // Pass the Error object, not just the message
      websiteId,
      scanId,
      filePath: detection.file_path
    }, {
      component: 'database',
      event: 'detection_error'
    });
    throw err;
  }
}

/**
 * Update the status of a scan detection
 * @param detectionId The ID of the scan detection to update
 * @param status The new status to set
 * @returns The updated scan detection
 */
export async function updateScanDetectionStatus(detectionId: string | number, status: string) {
  try {
    const query = `
      UPDATE scan_detections
      SET status = $1
      WHERE id = $2
      RETURNING id, status
    `;

    const values = [status, detectionId];

    const result = await pool.query(query, values);
    
    if (result.rows.length === 0) {
      throw new Error(`Scan detection with ID ${detectionId} not found`);
    }
    
    return result.rows[0];
  } catch (error) {
    // Ensure error is always an Error object
    const err = error instanceof Error ? error : new Error(String(error) || 'Unknown error');
    logger.error({
      message: 'Error updating scan detection status',
      error: err, // Pass the Error object, not just the message
      detectionId,
      status
    }, {
      component: 'database',
      event: 'update_scan_detection_status_error'
    });
    throw err;
  }
}

/**
 * Create a new quarantined detection record
 * @param detection The quarantined detection data
 * @returns The created quarantined detection
 */
export async function createQuarantinedDetection(detection: {
  scan_detection_id: number | null;
  quarantine_id: string;
  original_path: string;
  quarantine_path: string;
  timestamp: Date;
  scan_finding_id?: string | null;
  file_size?: number;
  file_type?: string;
  file_hash?: string | null;
  detection_type: string;
}) {
  try {
    const query = `
      INSERT INTO quarantined_detections (
        scan_detection_id, quarantine_id, original_path, quarantine_path, timestamp,
        scan_finding_id, file_size, file_type, file_hash, detection_type
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      RETURNING id
    `;

    const values = [
      detection.scan_detection_id,
      detection.quarantine_id,
      detection.original_path,
      detection.quarantine_path,
      detection.timestamp,
      detection.scan_finding_id || null,
      detection.file_size || 0,
      detection.file_type || 'unknown',
      detection.file_hash || null,
      detection.detection_type
    ];

    const result = await pool.query(query, values);
    return result.rows[0];
  } catch (error) {
    // Ensure error is always an Error object
    const err = error instanceof Error ? error : new Error(String(error) || 'Unknown error');
    logger.error({
      message: 'Error creating quarantined detection',
      error: err, // Pass the Error object, not just the message
      quarantineId: detection.quarantine_id,
      originalPath: detection.original_path
    }, {
      component: 'database',
      event: 'create_quarantined_detection_error'
    });
    throw err;
  }
}

/**
 * Remove a quarantined detection record by quarantine_id
 * @param quarantineId The quarantine ID to remove
 * @returns The deleted quarantined detection
 */
export async function removeQuarantinedDetection(quarantineId: string) {
  try {
    // First, get the scan_detection_id from the quarantined_detections table
    const getQuery = `
      SELECT scan_detection_id 
      FROM quarantined_detections 
      WHERE quarantine_id = $1
    `;
    
    const getResult = await pool.query(getQuery, [quarantineId]);
    
    if (getResult.rows.length === 0) {
      throw new Error(`Quarantined detection with ID ${quarantineId} not found`);
    }
    
    const scanDetectionId = getResult.rows[0].scan_detection_id;
    
    // Then delete the record
    const deleteQuery = `
      DELETE FROM quarantined_detections
      WHERE quarantine_id = $1
      RETURNING *
    `;

    const deleteResult = await pool.query(deleteQuery, [quarantineId]);
    
    if (deleteResult.rows.length === 0) {
      throw new Error(`Quarantined detection with ID ${quarantineId} not found`);
    }
    
    return { 
      deletedRecord: deleteResult.rows[0],
      scanDetectionId
    };
  } catch (error) {
    // Ensure error is always an Error object
    const err = error instanceof Error ? error : new Error(String(error) || 'Unknown error');
    logger.error({
      message: 'Error removing quarantined detection',
      error: err, // Pass the Error object, not just the message
      quarantineId
    }, {
      component: 'database',
      event: 'remove_quarantined_detection_error'
    });
    throw err;
  }
}

/**
 * Move a quarantined detection to deleted_detections and remove it from quarantined_detections
 * @param quarantineId The quarantine ID of the file to move
 * @returns The created deleted detection record
 */
export async function moveQuarantinedToDeleted(quarantineId: string) {
  try {
    // Start a transaction
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      
      // First, get the quarantined detection record
      const getQuery = `
        SELECT * FROM quarantined_detections 
        WHERE quarantine_id = $1
      `;
      
      const getResult = await client.query(getQuery, [quarantineId]);
      
      if (getResult.rows.length === 0) {
        throw new Error(`Quarantined detection with ID ${quarantineId} not found`);
      }
      
      const quarantinedDetection = getResult.rows[0];
      
      // Create a record in deleted_detections
      const insertQuery = `
        INSERT INTO deleted_detections (
          scan_detection_id, file_path, timestamp
        ) VALUES ($1, $2, $3)
        RETURNING id
      `;
      
      const insertValues = [
        quarantinedDetection.scan_detection_id,
        quarantinedDetection.original_path,
        new Date()
      ];
      
      const insertResult = await client.query(insertQuery, insertValues);
      
      // Update the scan detection status to 'deleted'
      if (quarantinedDetection.scan_detection_id) {
        const updateQuery = `
          UPDATE scan_detections
          SET status = 'deleted'
          WHERE id = $1
          RETURNING id, status
        `;
        
        await client.query(updateQuery, [quarantinedDetection.scan_detection_id]);
      }
      
      // Delete the record from quarantined_detections
      const deleteQuery = `
        DELETE FROM quarantined_detections
        WHERE quarantine_id = $1
      `;
      
      await client.query(deleteQuery, [quarantineId]);
      
      // Commit the transaction
      await client.query('COMMIT');
      
      return {
        deletedDetectionId: insertResult.rows[0].id,
        scanDetectionId: quarantinedDetection.scan_detection_id,
        filePath: quarantinedDetection.original_path
      };
    } catch (error) {
      // Rollback the transaction if any error occurs
      await client.query('ROLLBACK');
      throw error;
    } finally {
      // Release the client back to the pool
      client.release();
    }
  } catch (error) {
    // Ensure error is always an Error object
    const err = error instanceof Error ? error : new Error(String(error) || 'Unknown error');
    logger.error({
      message: 'Error moving quarantined detection to deleted',
      error: err, // Pass the Error object, not just the message
      quarantineId
    }, {
      component: 'database',
      event: 'move_quarantined_to_deleted_error'
    });
    throw err;
  }
}

/**
 * Handle scan detection versioning logic
 * 
 * This function implements the versioning logic for scan detections:
 * 1. If a file is detected and an active entry already exists, update the existing entry
 * 2. If a file was previously quarantined/deleted and reappears, create a new entry with incremented version
 * 3. If a similar file (based on name, size, hash) was detected elsewhere, treat as reinfection
 * 4. If it's a new detection, create a new entry with version 1
 * 
 * @param filePath The path of the detected file
 * @param websiteId The website ID
 * @param scanId The scan ID
 * @param detectionData Additional detection data
 * @returns The scan detection ID and whether it's a new detection or update
 */
export async function handleScanDetectionVersioning(
  filePath: string,
  websiteId: string,
  scanId: string,
  detectionData: any
): Promise<{ scanDetectionId: number; isNew: boolean; versionNumber: number }> {
  try {
    // Extract filename from path
    const fileName = filePath.split('/').pop() || '';
    const fileSize = detectionData.fileSize || 0;
    const fileHash = detectionData.fileHash || null;
    
    // First check: Exact path match
    const exactPathQuery = `
      SELECT id, status, version_number, file_path, file_hash, file_size 
      FROM scan_detections 
      WHERE file_path = $1 AND website_id = $2
      ORDER BY version_number DESC
    `;
    
    const exactResult = await pool.query(exactPathQuery, [filePath, websiteId]);
    
    // If no exact path match, check for similar files (potential reinfections)
    let similarResult = { rows: [] };
    
    if (exactResult.rows.length === 0) {
      // Build query conditions based on available data
      let conditions = [];
      let params = [websiteId];
      let paramIndex = 2; // Starting from $2
      
      // Always include website_id
      conditions.push(`website_id = $1`);
      
      // Add filename condition if available
      if (fileName) {
        conditions.push(`file_path LIKE $${paramIndex}`);
        params.push(`%${fileName}`);
        paramIndex++;
      }
      
      // Add file hash condition if available
      if (fileHash) {
        conditions.push(`file_hash = $${paramIndex}`);
        params.push(fileHash);
        paramIndex++;
      }
      
      // Add file size condition if available
      if (fileSize > 0) {
        conditions.push(`file_size = $${paramIndex}`);
        params.push(fileSize);
        paramIndex++;
      }
      
      // Only proceed with similarity check if we have at least 2 conditions beyond website_id
      if (conditions.length > 1) {
        const similarityQuery = `
          SELECT id, status, version_number, file_path, file_hash, file_size 
          FROM scan_detections 
          WHERE ${conditions.join(' AND ')}
          ORDER BY version_number DESC
        `;
        
        similarResult = await pool.query(similarityQuery, params);
        
        // Log the similarity check for debugging
        logger.debug({
          message: 'Checking for similar files',
          filePath,
          fileName,
          fileSize,
          fileHash: fileHash ? '(hash available)' : '(no hash)',
          matchCount: similarResult.rows.length,
          conditions: conditions.join(' AND ')
        }, {
          component: 'database',
          event: 'similarity_check'
        });
      }
    }
    
    // Combine results, prioritizing exact matches
    const result = exactResult.rows.length > 0 ? exactResult : similarResult;
    
    // Case 1: No existing detections - create new with version 1
    if (result.rows.length === 0) {
      const insertQuery = `
        INSERT INTO scan_detections (
          website_id, scan_id, file_path, threat_score, confidence, 
          detection_type, severity, description, file_hash, file_size, 
          context_type, risk_level, status, version_number
        ) VALUES (
          $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'active', 1
        )
        RETURNING id, version_number
      `;
      
      const insertValues = [
        websiteId,
        scanId,
        filePath,
        detectionData.threatScore || 0,
        detectionData.confidence || 0,
        detectionData.detectionType || 'unknown',
        detectionData.severity || 'low',
        detectionData.description || '',
        detectionData.fileHash || null,
        detectionData.fileSize || 0,
        detectionData.contextType || 'unknown',
        detectionData.riskLevel || 'low'
      ];
      
      const insertResult = await pool.query(insertQuery, insertValues);
      
      return {
        scanDetectionId: insertResult.rows[0].id,
        isNew: true,
        versionNumber: 1
      };
    }
    
    // Case 2: Has active detection - update it
    const activeDetection = result.rows.find(d => d.status === 'active');
    if (activeDetection) {
      const updateQuery = `
        UPDATE scan_detections
        SET scan_id = $1,
            threat_score = $2,
            confidence = $3,
            detection_type = $4,
            severity = $5,
            description = $6,
            file_hash = $7,
            file_size = $8,
            context_type = $9,
            risk_level = $10
        WHERE id = $11
        RETURNING id, version_number
      `;
      
      const updateValues = [
        scanId,
        detectionData.threatScore || 0,
        detectionData.confidence || 0,
        detectionData.detectionType || 'unknown',
        detectionData.severity || 'low',
        detectionData.description || '',
        detectionData.fileHash || null,
        detectionData.fileSize || 0,
        detectionData.contextType || 'unknown',
        detectionData.riskLevel || 'low',
        activeDetection.id
      ];
      
      const updateResult = await pool.query(updateQuery, updateValues);
      
      return {
        scanDetectionId: updateResult.rows[0].id,
        isNew: false,
        versionNumber: updateResult.rows[0].version_number
      };
    }
    
    // Case 3: Only has quarantined/deleted detections or similar files found elsewhere - create new with incremented version
    // This indicates reinfection
    const highestVersion = Math.max(...result.rows.map(d => d.version_number));
    const newVersionNumber = highestVersion + 1;
    
    // Log reinfection details
    const similarFilePath = result.rows[0]?.file_path;
    if (similarFilePath && similarFilePath !== filePath) {
      logger.info({
        message: 'Reinfection detected with similar file',
        originalPath: similarFilePath,
        newPath: filePath,
        websiteId,
        versionNumber: newVersionNumber,
        matchReasons: [
          fileName ? 'filename' : null,
          fileSize > 0 ? 'file_size' : null,
          fileHash ? 'file_hash' : null
        ].filter(Boolean).join(', ')
      }, {
        component: 'database',
        event: 'reinfection_detected'
      });
    }
    
    const reinfectionQuery = `
      INSERT INTO scan_detections (
        website_id, scan_id, file_path, threat_score, confidence, 
        detection_type, severity, description, file_hash, file_size, 
        context_type, risk_level, status, version_number
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'active', $13
      )
      RETURNING id, version_number
    `;
    
    const reinfectionValues = [
      websiteId,
      scanId,
      filePath,
      detectionData.threatScore || 0,
      detectionData.confidence || 0,
      detectionData.detectionType || 'unknown',
      detectionData.severity || 'low',
      detectionData.description || '',
      detectionData.fileHash || null,
      detectionData.fileSize || 0,
      detectionData.contextType || 'unknown',
      detectionData.riskLevel || 'low',
      newVersionNumber
    ];
    
    const reinfectionResult = await pool.query(reinfectionQuery, reinfectionValues);
    
    return {
      scanDetectionId: reinfectionResult.rows[0].id,
      isNew: true,
      versionNumber: newVersionNumber
    };
  } catch (error) {
    // Ensure error is always an Error object
    const err = error instanceof Error ? error : new Error(String(error) || 'Unknown error');
    logger.error({
      message: 'Error handling scan detection versioning',
      error: err,
      filePath,
      websiteId,
      scanId
    }, {
      component: 'database',
      event: 'handle_scan_detection_versioning_error'
    });
    throw err;
  }
}

export async function updateWebsiteScanResult(websiteId: string | number, scanId: string, scanData: {
  infected_files: number;
  total_files: number;
  completed_at: Date;
  duration: number;
  status?: 'pending' | 'completed' | 'failed';
  error_message?: string;
}) {
  try {
    logger.debug({
      message: 'Updating website scan result',
      websiteId,
      scanId,
      status: scanData.status
    }, {
      component: 'database',
      event: 'update_scan_result'
    });

    const result = await pool.query(
      `UPDATE website_scans 
       SET infected_files_count = $1, 
           total_files_count = $2,
           completed_at = $3, 
           duration_seconds = $4, 
           status = $5, 
           error_message = $6
       WHERE website_id = $7 AND scan_id = $8
       RETURNING id`,
      [
        scanData.infected_files,
        scanData.total_files,
        scanData.completed_at,
        scanData.duration,
        scanData.status || 'completed',
        scanData.error_message,
        websiteId,
        scanId
      ]
    );

    if (result.rowCount === 0) {
      // If no rows were updated, the scan record doesn't exist, so create it
      logger.info({
        message: 'No existing scan record found, creating new one',
        websiteId,
        scanId
      }, {
        component: 'database',
        event: 'scan_result_create_fallback'
      });

      // Fallback to creating a new record if update didn't affect any rows
      await createWebsiteScanResult(websiteId, {
        scan_id: scanId,
        infected_files: scanData.infected_files,
        total_files: scanData.total_files,
        // Since we don't have started_at in the update data, use completed_at minus duration
        started_at: new Date(scanData.completed_at.getTime() - (scanData.duration * 1000)),
        completed_at: scanData.completed_at,
        duration: scanData.duration,
        status: scanData.status,
        error_message: scanData.error_message
      });
      return;
    }

    logger.info({
      message: 'Website scan result updated',
      websiteId,
      scanId,
      status: scanData.status || 'completed'
    }, {
      component: 'database',
      event: 'scan_result_updated'
    });
  } catch (error: any) {
    logger.error({
      message: 'Error updating website scan result',
      error,
      websiteId,
      scanId
    }, {
      component: 'database',
      event: 'update_scan_result_error'
    });
    throw error;
  }
}

export default pool;