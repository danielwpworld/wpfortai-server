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
    const query = `
      INSERT INTO scan_detections (
        website_id, scan_id, file_path, threat_score, confidence, detection_type, 
        severity, description, file_hash, file_size, context_type, risk_level
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      RETURNING id
    `;

    const values = [
      websiteId,
      scanId,
      detection.file_path,
      detection.threat_score,
      detection.confidence,
      detection.detection_type,
      detection.severity,
      detection.description,
      detection.file_hash || null,
      detection.file_size,
      detection.context_type,
      detection.risk_level
    ];

    const result = await pool.query(query, values);
    return result.rows[0];
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

export default pool;