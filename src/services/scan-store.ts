import redis from '../config/redis';
import { ScanStartResponse, ScanStatus } from '../types/wpsec';

export interface StoredScanData {
  domain: string;
  scan_id: string;
  started_at: string;
  status: ScanStatus['status'];
  progress?: number;
  files_scanned?: string;
  total_files?: string;
  completed_at?: string;
  duration?: number;
  results_endpoint?: string;
  error?: string;
}

export class ScanStore {
  private static readonly SCAN_KEY_PREFIX = 'scan:';
  private static readonly ACTIVE_SCAN_KEY_PREFIX = 'active_scan:';
  private static readonly SCAN_TTL = 60 * 60 * 24; // 24 hours in seconds

  static async createScan(domain: string, scanData: ScanStartResponse): Promise<void> {
    const storedData: StoredScanData = {
      domain,
      scan_id: scanData.scan_id,
      started_at: scanData.started_at,
      status: 'pending'
    };

    const multi = redis.multi();
    
    // Store scan data with TTL
    multi.setex(
      `${this.SCAN_KEY_PREFIX}${scanData.scan_id}`,
      this.SCAN_TTL,
      JSON.stringify(storedData)
    );

    // Set this scan as the active scan for the domain
    multi.set(
      `${this.ACTIVE_SCAN_KEY_PREFIX}${domain}`,
      scanData.scan_id
    );

    await multi.exec();
  }

  static async updateScanStatus(scanId: string, status: ScanStatus): Promise<void> {
    const key = `${this.SCAN_KEY_PREFIX}${scanId}`;
    const existingData = await redis.get(key);
    
    if (!existingData) {
      throw new Error(`Scan ${scanId} not found in store`);
    }

    const storedData: StoredScanData = JSON.parse(existingData);
    const updatedData: StoredScanData = {
      ...storedData,
      status: status.status,
      progress: status.progress,
      files_scanned: status.files_scanned,
      total_files: status.total_files,
      completed_at: status.completed_at,
      duration: status.duration,
      results_endpoint: status.results_endpoint
    };

    await redis.setex(key, this.SCAN_TTL, JSON.stringify(updatedData));

    // If scan is completed or failed, remove it from active scans
    if (status.status === 'completed' || status.status === 'failed') {
      await redis.del(`${this.ACTIVE_SCAN_KEY_PREFIX}${storedData.domain}`);
    }
  }

  static async getScan(scanId: string): Promise<StoredScanData | null> {
    const data = await redis.get(`${this.SCAN_KEY_PREFIX}${scanId}`);
    return data ? JSON.parse(data) : null;
  }

  static async getActiveScan(domain: string): Promise<StoredScanData | null> {
    const scanId = await redis.get(`${this.ACTIVE_SCAN_KEY_PREFIX}${domain}`);
    if (!scanId) return null;
    return this.getScan(scanId);
  }
}
