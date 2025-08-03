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
  id: string; // UUID
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

export async function getWebsiteById(id: string): Promise<Website | null> {
  logger.debug({
    message: 'Looking up website by ID',
    id
  }, {
    component: 'database',
    event: 'website_lookup_by_id'
  });

  try {
    const result = await pool.query<Website>(
      'SELECT * FROM websites WHERE id = $1',
      [id]
    );

    const website = result.rows[0] || null;
    logger.debug({
      message: website ? 'Website found' : 'Website not found',
      id,
      found: !!website
    }, {
      component: 'database',
      event: 'website_lookup_by_id_result'
    });

    return website;
  } catch (error: any) {
    logger.error({
      message: 'Error looking up website by ID',
      error,
      id
    }, {
      component: 'database',
      event: 'website_lookup_by_id_error'
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

/**
 * Insert a new core reinstall record into the website_core_reinstalls table
 * @param data - Object containing all relevant fields for the core reinstall
 */
export async function createCoreReinstallRecord(data: {
  website_id: string;
  operation_id: string;
  status?: string;
  message?: string;
  version?: string;
  check_status_endpoint?: string;
  started_at?: string | Date;
}) {
  try {
    const {
      website_id,
      operation_id,
      status,
      message,
      version,
      check_status_endpoint,
      started_at
    } = data;
    await pool.query(
      `INSERT INTO website_core_reinstalls (
        website_id, operation_id, status, message, version, check_status_endpoint, started_at, created_at, updated_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())`,
      [
        website_id,
        operation_id,
        status || null,
        message || null,
        version || null,
        check_status_endpoint || null,
        started_at ? new Date(started_at) : null
      ]
    );
    logger.info({
      message: 'Inserted website_core_reinstalls record',
      website_id,
      operation_id,
      status,
      version
    }, {
      component: 'database',
      event: 'core_reinstall_record_created'
    });
  } catch (error) {
    const err = error instanceof Error ? error : new Error(String(error) || 'Unknown error');
    logger.error({
      message: 'Error inserting website_core_reinstalls record',
      error: err,
      website_id: data.website_id,
      operation_id: data.operation_id
    }, {
      component: 'database',
      event: 'core_reinstall_record_error'
    });
    throw err;
  }
}

export async function createScanDetection(websiteId: string | number, scanId: string, detection: {
  file_path: string;
  threat_score: number;
  confidence: number;
  detection_type: string | string[];
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
/**
 * Update the status of a scan detection by scan_id and file_path
 * @param scanId The scan ID
 * @param filePath The file path
 * @param status The new status to set
 * @returns The number of rows updated
 */
export async function updateScanDetectionByPath(scanId: string, filePath: string, status: string) {
  try {
    const query = `
      UPDATE scan_detections
      SET status = $1
      WHERE scan_id = $2 AND file_path = $3
      RETURNING id, status, file_path
    `;

    const values = [status, scanId, filePath];

    const result = await pool.query(query, values);
    
    logger.debug({
      message: 'Updated scan detection by path',
      scanId,
      filePath,
      status,
      rowsAffected: result.rowCount,
      updatedRows: result.rows
    }, {
      component: 'database',
      event: 'update_scan_detection_by_path'
    });
    
    return {
      rowsAffected: result.rowCount,
      updatedRows: result.rows
    };
  } catch (error) {
    // Ensure error is always an Error object
    const err = error instanceof Error ? error : new Error(String(error) || 'Unknown error');
    logger.error({
      message: 'Error updating scan detection by path',
      error: err,
      scanId,
      filePath,
      status
    }, {
      component: 'database',
      event: 'update_scan_detection_by_path_error'
    });
    throw err;
  }
}

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
  detection_type: string | string[];
  confidence?: number;
  threat_score?: number;
}) {
  try {
    const query = `
      INSERT INTO quarantined_detections (
        scan_detection_id, quarantine_id, original_path, quarantine_path, timestamp, scan_finding_id, file_size, file_type, file_hash, detection_type, confidence, threat_score
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      RETURNING *
    `;

    // Normalize detection_type to a proper PostgreSQL array format
    let normalizedDetectionType;
    if (Array.isArray(detection.detection_type)) {
      // Format as PostgreSQL array: '{val1,val2,val3}'
      normalizedDetectionType = `{${detection.detection_type.map(type => `"${type}"`).join(',')}}`;  
    } else if (typeof detection.detection_type === 'string') {
      // If it's a single string, convert to a single-element array
      normalizedDetectionType = `{"${detection.detection_type}"}`;  
    } else {
      // Default to an empty array if undefined or null
      normalizedDetectionType = '{}'; 
    }

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
      normalizedDetectionType,
      detection.confidence || 0,
      detection.threat_score || 0
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
        Array.isArray(detectionData.detectionType) ? detectionData.detectionType : [detectionData.detectionType || 'unknown'],
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
        Array.isArray(detectionData.detectionType) ? detectionData.detectionType : [detectionData.detectionType || 'unknown'],
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
      Array.isArray(detectionData.detectionType) ? detectionData.detectionType : [detectionData.detectionType || 'unknown'],
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

/**
 * Updates the network_status field in the website_data table after whitelist/blocklist changes
 * @param websiteId The UUID of the website
 * @param ip The IP address that was added or removed
 * @param listType The type of list (whitelist or blocklist)
 * @param action The action performed (add/remove for whitelist, block/unblock for blocklist)
 */
/**
 * Updates the network_status.active field in the website_data table when firewall is toggled
 * @param websiteId The UUID of the website
 * @param active Whether the firewall is active (1) or inactive (0)
 */
/**
 * Updates the network_layer field in the website_data table with firewall logs data
 * @param websiteId The UUID of the website
 * @param firewallLogs The firewall logs data from WPSec API
 */
export async function updateNetworkLayer(
  websiteId: string,
  firewallLogs: any
): Promise<void> {
  try {
    logger.debug({
      message: 'Updating network_layer with firewall logs data',
      websiteId
    }, {
      component: 'database',
      event: 'update_network_layer'
    });

    // First, check if website_data record exists
    const checkQuery = `
      SELECT id, network_layer FROM website_data 
      WHERE website_id = $1
    `;
    const checkResult = await pool.query(checkQuery, [websiteId]);
    
    let networkLayer: any = {};
    
    if (checkResult.rows.length === 0) {
      logger.debug({
        message: 'No website_data record found, will create new network_layer',
        websiteId
      }, {
        component: 'database',
        event: 'update_network_layer_no_record'
      });
    } else {
      // Get existing network_layer or initialize if not exists
      networkLayer = checkResult.rows[0].network_layer || {};
    }

    // The API response has a different structure than we expected
    // It contains a success field and a data field that contains all the actual data
    const apiData = firewallLogs.data || firewallLogs;
    
    // Process the firewall logs into the expected network_layer format
    const processedData = {
      data: {
        trends: {
          attacks_by_day: apiData.trends?.attacks_by_day || []
        },
        summary: {
          period_days: "7", // We're using 7 days as the period
          total_blocks: apiData.summary?.total_blocks || 0,
          critical_attacks: apiData.summary?.critical_attacks || 0
        },
        top_threats: {
          ips: apiData.top_threats?.ips || [],
          rules: apiData.top_threats?.rules || [],
          countries: apiData.top_threats?.countries || []
        },
        recent_blocks: apiData.recent_blocks || []
      },
      success: true
    };

    // Update or insert the website_data record
    const upsertQuery = `
      INSERT INTO website_data (website_id, network_layer, fetched_at)
      VALUES ($1, $2, NOW())
      ON CONFLICT (website_id)
      DO UPDATE SET 
        network_layer = $2,
        fetched_at = NOW()
    `;
    
    await pool.query(upsertQuery, [websiteId, JSON.stringify(processedData)]);

    logger.info({
      message: 'Updated network_layer with firewall logs data',
      websiteId,
      recentBlocksCount: processedData.data.recent_blocks.length,
      totalBlocks: processedData.data.summary.total_blocks
    }, {
      component: 'database',
      event: 'update_network_layer_success'
    });
  } catch (error) {
    logger.error({
      message: 'Error updating network_layer',
      error: error instanceof Error ? error : new Error(String(error) || 'Unknown error'),
      websiteId
    }, {
      component: 'database',
      event: 'update_network_layer_error'
    });
    throw error;
  }
}

export async function updateFirewallStatus(
  websiteId: string,
  active: boolean
): Promise<void> {
  try {
    logger.debug({
      message: 'Updating network_status.active after firewall toggle',
      websiteId,
      active
    }, {
      component: 'database',
      event: 'update_firewall_status'
    });

    // First, check if website_data record exists
    const checkQuery = `
      SELECT id, network_status FROM website_data 
      WHERE website_id = $1
    `;
    const checkResult = await pool.query(checkQuery, [websiteId]);
    
    if (checkResult.rows.length === 0) {
      logger.debug({
        message: 'No website_data record found, will be created by background job',
        websiteId
      }, {
        component: 'database',
        event: 'update_firewall_status_no_record'
      });
      return;
    }

    // Get current network_status or initialize if not exists
    const networkStatus = checkResult.rows[0].network_status || {};
    
    // Update the active field - convert boolean to string "1" or "0"
    networkStatus.active = active ? "1" : "0";

    // Update the database
    const updateQuery = `
      UPDATE website_data 
      SET network_status = $1, 
          fetched_at = NOW() 
      WHERE website_id = $2
    `;
    await pool.query(updateQuery, [JSON.stringify(networkStatus), websiteId]);

    logger.info({
      message: 'Updated network_status.active after firewall toggle',
      websiteId,
      active
    }, {
      component: 'database',
      event: 'update_firewall_status_success'
    });
  } catch (error) {
    logger.error({
      message: 'Error updating network_status.active',
      error: error instanceof Error ? error : new Error(String(error) || 'Unknown error'),
      websiteId,
      active
    }, {
      component: 'database',
      event: 'update_firewall_status_error'
    });
    throw error;
  }
}

export async function updateNetworkStatus(
  websiteId: string,
  ip: string,
  listType: 'whitelist' | 'blocklist',
  action: 'add' | 'remove' | 'block' | 'unblock'
): Promise<void> {
  try {
    logger.debug({
      message: 'Updating network_status after IP list change',
      websiteId,
      ip,
      listType,
      action
    }, {
      component: 'database',
      event: 'update_network_status'
    });

    // First, check if website_data record exists
    const checkQuery = `
      SELECT id, network_status FROM website_data 
      WHERE website_id = $1
    `;
    const checkResult = await pool.query(checkQuery, [websiteId]);
    
    if (checkResult.rows.length === 0) {
      logger.debug({
        message: 'No website_data record found, will be created by background job',
        websiteId
      }, {
        component: 'database',
        event: 'update_network_status_no_record'
      });
      return;
    }

    const networkStatus = checkResult.rows[0].network_status || {};
    
    // Map action to the appropriate list and operation
    let listKey: string;
    let operation: 'add' | 'remove';
    
    if (listType === 'whitelist') {
      listKey = 'whitelisted_ips';
      operation = action as 'add' | 'remove';
    } else { // blocklist
      listKey = 'blocklisted_ips';
      operation = action === 'block' ? 'add' : 'remove';
    }

    // Ensure the list exists
    if (!networkStatus[listKey]) {
      networkStatus[listKey] = [];
    }

    // Update the list
    if (operation === 'add' && !networkStatus[listKey].includes(ip)) {
      networkStatus[listKey].push(ip);
    } else if (operation === 'remove') {
      networkStatus[listKey] = networkStatus[listKey].filter((item: string) => item !== ip);
    }

    // Update the database
    const updateQuery = `
      UPDATE website_data 
      SET network_status = $1, 
          fetched_at = NOW() 
      WHERE website_id = $2
    `;
    await pool.query(updateQuery, [JSON.stringify(networkStatus), websiteId]);

    logger.info({
      message: 'Updated network_status after IP list change',
      websiteId,
      ip,
      listType,
      action
    }, {
      component: 'database',
      event: 'update_network_status_success'
    });
  } catch (error) {
    logger.error({
      message: 'Error updating network_status',
      error: error instanceof Error ? error : new Error(String(error) || 'Unknown error'),
      websiteId,
      ip,
      listType,
      action
    }, {
      component: 'database',
      event: 'update_network_status_error'
    });
    throw error;
  }
}

/**
 * Create multiple scan detections in a single database operation
 * This is much more efficient than creating detections one by one
 * @param websiteId The UUID of the website
 * @param scanId The scan ID
 * @param detections Array of detection objects
 * @param batchSize Maximum number of detections to insert in a single query (default: 500)
 * @returns Array of created detection IDs
 */
export async function batchCreateScanDetections(
  websiteId: string,
  scanId: string,
  detections: Array<{
    file_path: string;
    threat_score: number;
    confidence: number;
    detection_type: string | string[];
    severity: string;
    description: string;
    file_hash?: string;
    file_size: number;
    context_type: string;
    risk_level: string;
  }>,
  batchSize = 500
): Promise<number[]> {
  if (!detections.length) {
    return [];
  }

  try {
    logger.debug({
      message: 'Batch creating scan detections',
      websiteId,
      scanId,
      detectionCount: detections.length,
      batchSize
    }, {
      component: 'database',
      event: 'batch_create_detections'
    });

    const createdIds: number[] = [];
    
    // Process in batches to avoid exceeding query size limits
    for (let i = 0; i < detections.length; i += batchSize) {
      const batch = detections.slice(i, i + batchSize);
      
      // Build the query parts
      let valuesSql: string[] = [];
      const params: any[] = [];
      let paramIndex = 1;
      
      for (const detection of batch) {
        // Format detection_type as a PostgreSQL array string
        const detectionType = Array.isArray(detection.detection_type) 
          ? detection.detection_type 
          : [detection.detection_type || 'unknown'];
          
        const normalizedDetectionType = `{${detectionType.map(type => `"${type}"`).join(',')}}`;  
        
        // Add values placeholder for this detection
        valuesSql.push(`($${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++})`);
        
        // Add parameter values in the same order
        // Ensure threat_score is converted to an integer
        const threatScore = typeof detection.threat_score === 'string' 
          ? parseInt(detection.threat_score, 10) || 0 
          : Math.floor(Number(detection.threat_score) || 0);
          
        // Ensure confidence is converted to an integer
        const confidence = typeof detection.confidence === 'string' 
          ? parseInt(detection.confidence, 10) || 0 
          : Math.floor(Number(detection.confidence) || 0);
          
        params.push(
          websiteId,
          scanId,
          detection.file_path,
          threatScore,
          confidence,
          normalizedDetectionType,
          detection.severity || 'low',
          detection.description || '',
          detection.file_hash || null,
          detection.file_size || 0,
          detection.context_type || 'unknown',
          detection.risk_level || 'low',
          'active', // status
          1 // version_number (all new detections start at version 1)
        );
      }
      
      // Construct the full query
      const query = `
        INSERT INTO scan_detections (
          website_id, scan_id, file_path, threat_score, confidence, 
          detection_type, severity, description, file_hash, file_size, 
          context_type, risk_level, status, version_number
        ) VALUES 
        ${valuesSql.join(', ')}
        RETURNING id
      `;
      
      // Execute the batch insert
      const result = await pool.query(query, params);
      
      // Collect the created IDs
      const ids = result.rows.map(row => row.id);
      createdIds.push(...ids);
      
      logger.debug({
        message: 'Batch insert completed',
        batchSize: batch.length,
        createdCount: ids.length,
        batchNumber: Math.floor(i / batchSize) + 1,
        totalBatches: Math.ceil(detections.length / batchSize)
      }, {
        component: 'database',
        event: 'batch_insert_completed'
      });
    }
    
    logger.info({
      message: 'Batch creation of scan detections completed',
      websiteId,
      scanId,
      totalDetections: detections.length,
      createdCount: createdIds.length
    }, {
      component: 'database',
      event: 'batch_create_detections_completed'
    });
    
    return createdIds;
  } catch (error) {
    const err = error instanceof Error ? error : new Error(String(error) || 'Unknown error');
    logger.error({
      message: 'Error batch creating scan detections',
      error: err,
      websiteId,
      scanId,
      detectionCount: detections.length
    }, {
      component: 'database',
      event: 'batch_create_detections_error'
    });
    throw err;
  }
}

/**
 * Update the wpcore_layer field for a website in the website_data table
 * @param websiteId The UUID of the website
 * @param wpcoreLayer The new wpcore_layer JSON object
 */
export async function updateWPCoreLayer(websiteId: string, wpcoreLayer: any): Promise<void> {
  try {
    await pool.query(
      `UPDATE website_data SET wpcore_layer = $1, fetched_at = NOW() WHERE website_id = $2`,
      [wpcoreLayer, websiteId]
    );
    logger.info({
      message: 'Updated wpcore_layer',
      websiteId,
    }, {
      component: 'database',
      event: 'update_wpcore_layer_success'
    });
  } catch (error) {
    logger.error({
      message: 'Error updating wpcore_layer',
      error: error instanceof Error ? error : new Error(String(error) || 'Unknown error'),
      websiteId,
    }, {
      component: 'database',
      event: 'update_wpcore_layer_error'
    });
    throw error;
  }
}

/**
 * Update the status and message of a core reinstall record in website_core_reinstalls
 * @param operation_id The operation ID of the core reinstall
 * @param updates Object with status and/or message to update
 */
export async function updateCoreReinstallRecord(
  operation_id: string,
  updates: { status?: string; message?: string }
) {
  if (!operation_id) throw new Error('operation_id is required');
  if (!updates.status && !updates.message) return;

  // Build dynamic SET clause
  const setClauses = [];
  const values = [];
  let idx = 1;
  if (updates.status !== undefined) {
    setClauses.push(`status = $${idx++}`);
    values.push(updates.status);
  }
  if (updates.message !== undefined) {
    setClauses.push(`message = $${idx++}`);
    values.push(updates.message);
  }
  setClauses.push(`updated_at = NOW()`);
  const query = `UPDATE website_core_reinstalls SET ${setClauses.join(', ')} WHERE operation_id = $${idx}`;
  values.push(operation_id);

  // Debugging output
  logger.debug({
    message: 'About to update website_core_reinstalls',
    query,
    values,
    databaseUrl: process.env.DATABASE_URL
  }, {
    component: 'database',
    event: 'core_reinstall_record_update_debug'
  });

  try {
    const result = await pool.query(query, values);
    if (result.rowCount === 0) {
      logger.warn({ message: 'No website_core_reinstalls record found to update', operation_id, updates }, {
        component: 'database',
        event: 'core_reinstall_record_update_not_found'
      });
    } else {
      logger.info({ message: 'Updated website_core_reinstalls record', operation_id, updates }, {
        component: 'database',
        event: 'core_reinstall_record_updated'
      });
    }
  } catch (error) {
    const err = error instanceof Error ? error : new Error(String(error) || 'Unknown error');
    logger.error({ message: 'Error updating website_core_reinstalls record', error: err, operation_id, updates }, {
      component: 'database',
      event: 'core_reinstall_record_update_error'
    });
    throw err;
  }
}

export default pool;