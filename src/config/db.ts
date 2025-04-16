import { Pool } from 'pg';
import { config } from 'dotenv';

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

export interface Website {
  id: number;
  domain: string;
  user_id: number;
  created_at: Date;
  updated_at: Date;
}

export async function getWebsiteByDomain(domain: string): Promise<Website | null> {
  const result = await pool.query<Website>(
    'SELECT * FROM websites WHERE domain = $1',
    [domain]
  );
  return result.rows[0] || null;
}

export async function createWebsiteScanResult(websiteId: number, scanData: {
  scan_id: string;
  infected_files: number;
  total_files: number;
  started_at: Date;
  completed_at: Date;
  duration: number;
  status?: 'completed' | 'failed';
  error_message?: string;
}) {
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
}

export async function createScanDetection(websiteId: number, scanId: string, detection: {
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
}

export default pool;