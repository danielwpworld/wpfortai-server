import redis from '../config/redis';
import { ScanStartResponse, ScanStatus } from '../types/wpsec';
import pool from '../config/db';

export interface StoredScanData {
  website_id: string;
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
  private static readonly ACTIVE_SCAN_KEY_PREFIX = 'active_scan_website:';
  private static readonly SCAN_TTL = 60 * 60 * 2; // 2 hours in seconds

  /**
   * Clean up any stale scans for a website before creating a new one
   */
  static async cleanupStaleScans(websiteId: string): Promise<void> {
    try {
      // Remove any active scan markers for this website
      await redis.del(`${this.ACTIVE_SCAN_KEY_PREFIX}${websiteId}`);
      
      // Mark pending DB scans as 'failed' with cleanup timestamp
      await pool.query(`
        UPDATE website_scans 
        SET status = 'failed', 
            error_message = 'Cleaned up stale scan',
            completed_at = NOW()
        WHERE website_id = $1 AND status = 'pending'
      `, [websiteId]);
      
      console.log(`Cleaned up stale scans for website ${websiteId}`);
    } catch (error) {
      console.error(`Error cleaning up stale scans for website ${websiteId}:`, error);
    }
  }

  /**
   * Create a new scan with automatic cleanup of stale scans
   */
  static async createScanWithCleanup(websiteId: string, domain: string, scanData: ScanStartResponse): Promise<void> {
    // ALWAYS cleanup first to prevent conflicts
    await this.cleanupStaleScans(websiteId);
    
    const storedData: StoredScanData = {
      website_id: websiteId,
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

    // Set this scan as the active scan for the website (using website_id, not domain)
    multi.set(
      `${this.ACTIVE_SCAN_KEY_PREFIX}${websiteId}`,
      scanData.scan_id
    );

    await multi.exec();
  }

  /**
   * Legacy method - kept for backward compatibility but deprecated
   * @deprecated Use createScanWithCleanup instead
   */
  static async createScan(domain: string, scanData: ScanStartResponse): Promise<void> {
    console.warn('createScan is deprecated, use createScanWithCleanup instead');
    const storedData: StoredScanData = {
      website_id: '', // Will be empty for legacy calls
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

    // Legacy: Set this scan as the active scan for the domain
    multi.set(
      `active_scan:${domain}`,
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
      results_endpoint: '/results' // Always use the correct endpoint
    };

    await redis.setex(key, this.SCAN_TTL, JSON.stringify(updatedData));

    // If scan is completed or failed, remove it from active scans
    if (status.status === 'completed' || status.status === 'failed') {
      // Remove from both new website_id-based key and legacy domain-based key
      if (storedData.website_id) {
        await redis.del(`${this.ACTIVE_SCAN_KEY_PREFIX}${storedData.website_id}`);
      }
      // Legacy cleanup
      await redis.del(`active_scan:${storedData.domain}`);
    }
  }

  static async getScan(scanId: string): Promise<StoredScanData | null> {
    const data = await redis.get(`${this.SCAN_KEY_PREFIX}${scanId}`);
    return data ? JSON.parse(data) : null;
  }

  /**
   * Get active scan by website ID (recommended method)
   */
  static async getActiveScanByWebsiteId(websiteId: string): Promise<StoredScanData | null> {
    const scanId = await redis.get(`${this.ACTIVE_SCAN_KEY_PREFIX}${websiteId}`);
    if (!scanId) return null;
    
    const scanData = await this.getScan(scanId);
    if (!scanData) {
      // Clean up orphaned reference
      await redis.del(`${this.ACTIVE_SCAN_KEY_PREFIX}${websiteId}`);
      return null;
    }
    
    // Verify scan belongs to correct website
    if (scanData.website_id && scanData.website_id !== websiteId) {
      await this.cleanupStaleScans(websiteId);
      return null;
    }
    
    return scanData;
  }

  /**
   * Legacy method - get active scan by domain
   * @deprecated Use getActiveScanByWebsiteId instead
   */
  static async getActiveScan(domain: string): Promise<StoredScanData | null> {
    console.warn('getActiveScan by domain is deprecated, use getActiveScanByWebsiteId instead');
    const scanId = await redis.get(`active_scan:${domain}`);
    if (!scanId) return null;
    return this.getScan(scanId);
  }
}
