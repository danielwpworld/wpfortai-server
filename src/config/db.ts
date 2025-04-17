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
    logger.debug({
      message: 'Creating scan detection',
      websiteId,
      scanId,
      filePath: detection.file_path,
      detectionType: detection.detection_type,
      severity: detection.severity
    }, {
      component: 'database',
      event: 'create_detection'
    });

    await pool.query(
      `INSERT INTO scan_detections (
        website_id, scan_id, file_path, threat_score, confidence,
        detection_type, severity, description, file_hash, file_size,
        context_type, risk_level
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
      [
        websiteId,
        scanId,
        detection.file_path,
        detection.threat_score,
        detection.confidence,
        detection.detection_type,
        detection.severity,
        detection.description,
        detection.file_hash,
        detection.file_size,
        detection.context_type,
        detection.risk_level
      ]
    );

    logger.info({
      message: 'Scan detection created',
      websiteId,
      scanId,
      filePath: detection.file_path,
      severity: detection.severity
    }, {
      component: 'database',
      event: 'detection_created'
    });
  } catch (error: any) {
    logger.error({
      message: 'Error creating scan detection',
      error,
      websiteId,
      scanId,
      filePath: detection.file_path
    }, {
      component: 'database',
      event: 'detection_error'
    });
    throw error;
  }
}

export default pool;