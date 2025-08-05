// Lazy import of node-fetch to prevent immediate execution
// Import type only
import type { RequestInit } from 'node-fetch';
import type { 
  ScanStartResponse, 
  ScanStatus, 
  ScanResults, 
  SiteInfo, 
  Vulnerability, 
  FirewallStatus, 
  FirewallLog, 
  BackupStatus, 
  BackupListItem, 
  WhitelistedFile, 
  QuarantineResponse, 
  QuarantineListResponse, 
  QuarantineRestoreResponse, 
  BatchOperationResponse, 
  CoreCheckResult,
  Detection,
  FileContext,
  InfectedFile,
  QuarantinedFile,
  BatchOperationResult
} from '../types/wpsec';
import { ScanStore } from './scan-store';

// Lazy loading of fetch
let fetch: any;

// Initialize fetch only when needed
const initFetch = async () => {
  if (!fetch) {
    const nodeFetch = await import('node-fetch');
    fetch = nodeFetch.default;
  }
  return fetch;
};

export class WPSecAPI {
  private readonly apiKey: string;
  private readonly domain: string;

  constructor(domain: string = 'sub2.test-wpworld.uk') {
    this.apiKey = process.env.WPFORT_API_KEY || '';
    if (!this.apiKey) {
      throw new Error('WPFORT_API_KEY is not set in environment variables');
    }
    this.domain = domain;
  }

  private async request<T>(endpoint: string, options: Partial<Omit<RequestInit, 'body'>> & { 
    body?: any, 
    queryParams?: Record<string, string> 
  } = {}): Promise<T> {
    const requestOptions: RequestInit = {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': this.apiKey,
        ...options.headers,
      }
    };

    if (options.body) {
      requestOptions.body = JSON.stringify(options.body);
    }
    const baseUrl = this.domain.startsWith('http') ? this.domain : `https://${this.domain}`;
    const url = new URL(baseUrl);
    url.searchParams.append('wpsec_endpoint', endpoint);
    
    // Handle custom headers that should be converted to query parameters
    const customHeaders = requestOptions.headers as Record<string, string>;
    if (customHeaders && 'x-period' in customHeaders) {
      url.searchParams.append('period', customHeaders['x-period']);
      // Remove from headers as it's now in the URL
      delete customHeaders['x-period'];
    }
    
    // Add any additional query parameters
    if (options.queryParams) {
      Object.entries(options.queryParams).forEach(([key, value]) => {
        url.searchParams.append(key, value);
      });
    }

    const fetchFn = await initFetch();
    const response = await fetchFn(url.toString(), requestOptions);

    if (!response.ok) {
      try {
        const errorText = await response.text();
        console.error(`WPSec API error (${response.status} ${response.statusText}): ${errorText}`);
        throw new Error(`WPSec API error: ${response.statusText} - ${errorText}`);
      } catch (textError) {
        throw new Error(`WPSec API error: ${response.statusText}`);
      }
    }

    return response.json() as Promise<T>;
  }

  // Site Information
  async getSiteInfo(): Promise<SiteInfo> {
    return this.request<SiteInfo>('site-info');
  }

  // Vulnerabilities
  async getVulnerabilities(): Promise<Vulnerability[]> {
    return this.request<Vulnerability[]>('vulnerabilities');
  }

  // Scanning
  async startScan(): Promise<ScanStartResponse> {
    const response = await this.request<ScanStartResponse>('scan', {
      method: 'POST'
    });

    // Store scan data in Redis
    await ScanStore.createScan(this.domain, response);

    return response;
  }

  async getScanStatus(scanId: string): Promise<ScanStatus> {
    const status = await this.request<ScanStatus>(`scan/${scanId}/status`);
    
    // Update scan status in Redis
    await ScanStore.updateScanStatus(scanId, status);

    return status;
  }

  async getScanResults(scanId?: string): Promise<ScanResults> {
    // WPSec API only supports getting the latest scan results, scanId is ignored
    return this.request<ScanResults>('results');
  }

  // Firewall Management
  async toggleFirewall(active: boolean): Promise<void> {
    return this.request('firewall/toggle', {
      method: 'POST',
      body: { active }
    });
  }

  async getFirewallStatus(): Promise<FirewallStatus> {
    return this.request<FirewallStatus>('firewall/status');
  }

  async getFirewallLogs(period: number = 7): Promise<FirewallLog[]> {
    // The period parameter should be passed as a query parameter, not in the endpoint path
    // The WPSec API expects: ?wpsec_endpoint=firewall/logs&period=7
    return this.request<FirewallLog[]>('firewall/logs', {
      method: 'GET',
      headers: {
        'x-period': String(period)
      }
    });
  }

  async whitelistFirewallIP(ip: string, action: 'add' | 'remove'): Promise<void> {
    return this.request('firewall/whitelist', {
      method: 'POST',
      body: { ip, action }
    });
  }

  /**
   * Block or unblock an IP address or CIDR range in the firewall
   * @param ip IP address or CIDR range to block/unblock
   * @param action Whether to block or unblock the IP
   */
  async blocklistFirewallIP(ip: string, action: 'block' | 'unblock'): Promise<void> {
    return this.request('firewall/blocklist', {
      method: 'POST',
      body: { ip, action }
    });
  }

  // Backup Management
  async startBackup(type: string, incremental?: boolean): Promise<{ backup_id: string }> {
    return this.request<{ backup_id: string }>('backup/start', {
      method: 'POST',
      body: { type, incremental }
    });
  }

  async getBackupStatus(backupId: string): Promise<BackupStatus> {
    return this.request<BackupStatus>(`backup/status/${backupId}`);
  }

  async listBackups(): Promise<BackupListItem[]> {
    return this.request<BackupListItem[]>('backup/list');
  }

  async restoreBackup(backupId: string): Promise<{ restore_id: string }> {
    return this.request<{ restore_id: string }>(`backup/restore/${backupId}`, {
      method: 'POST'
    });
  }

  async getRestoreStatus(restoreId: string): Promise<BackupStatus> {
    return this.request<BackupStatus>(`backup/restore/status/${restoreId}`);
  }

  // WordPress Core Management
  async checkCoreIntegrity(): Promise<CoreCheckResult> {
    return this.request<CoreCheckResult>('core-check');
  }

  /**
   * Reinstall WordPress core using the default payload
   * @param payload Optional custom payload, defaults to recommended options
   */
  async coreReinstall(payload: {
    version?: string;
    backup?: boolean;
    skip_content?: boolean;
    skip_config?: boolean;
    verify_checksums?: boolean;
  } = {
    version: 'current',
    backup: true,
    skip_content: true,
    skip_config: true,
    verify_checksums: true
  }): Promise<any> {
    return this.request('core-reinstall', {
      method: 'POST',
      body: payload
    });
  }

  async updateAll(update_id?: string): Promise<void> {
    return this.request('update-all', {
      method: 'POST',
      body: update_id ? { update_id } : undefined
    });
  }

  async updateItems(type: 'plugins' | 'themes' | 'wordpress', items: string[], update_id?: string): Promise<any> {
    return this.request('update-items', {
      method: 'POST',
      body: { type, items, update_id }
    });
  }

  // File Management
  async whitelistFile(filePath: string | string[], reason?: string, addedBy?: string): Promise<void> {
    const body = Array.isArray(filePath)
      ? { file_paths: filePath, reason, added_by: addedBy }
      : { file_path: filePath, reason, added_by: addedBy };
    return this.request('whitelist', {
      method: 'POST',
      body
    });
  }

  /**
   * Inspect a file to get detailed information and potential detections
   * @param filePath Path to the file to inspect
   * @returns Detailed file information including detections if any are found
   */
  async inspectFile(filePath: string): Promise<any> {
    return this.request('inspect-file', {
      method: 'POST',
      body: { file_path: filePath }
    });
  }

  /**
   * Check the health of the WPSec plugin on the site
   * @returns Plugin status information including active state and version
   */
  async ping(): Promise<{
    success: boolean;
    data: {
      plugin_active: boolean;
      plugin_version: string;
    };
  }> {
    return this.request('ping');
  }

  /**
   * Fix file/directory permissions on the WordPress site
   * @param options Options for fixing permissions (fix_all or specific path)
   * @returns Result of the permission fix operation
   */
  async fixPermissions(options: {
    fix_all?: boolean;
    path?: string;
    recursive?: boolean;
    type?: 'file' | 'directory';
  }): Promise<any> {
    return this.request('fix-permissions', {
      method: 'POST',
      body: options
    });
  }

  async getWhitelistedFiles(includeDetails?: boolean, verifyIntegrity?: boolean): Promise<WhitelistedFile[]> {
    let endpoint = 'whitelist/list';
    if (includeDetails) endpoint += '?include_details=1';
    if (verifyIntegrity) endpoint += `${includeDetails ? '&' : '?'}verify_integrity=1`;
    return this.request<WhitelistedFile[]>(endpoint);
  }

  async removeWhitelistedFile(filePath: string): Promise<void> {
    return this.request('whitelist/remove', {
      method: 'POST',
      body: { file_path: filePath }
    });
  }

  async verifyWhitelistIntegrity(): Promise<{ status: string; modified: string[]; missing: string[] }> {
    return this.request('whitelist/verify');
  }

  async cleanupWhitelist(): Promise<void> {
    return this.request('whitelist/cleanup', {
      method: 'POST'
    });
  }

  // Quarantine Management
  async quarantineFile(filePath: string): Promise<QuarantineResponse> {
    return this.request<QuarantineResponse>('quarantine', {
      method: 'POST',
      body: { file_path: filePath }
    });
  }

  async getQuarantinedFiles(): Promise<QuarantineListResponse> {
    return this.request<QuarantineListResponse>('quarantine-list');
  }

  async restoreQuarantinedFile(
    quarantineIdOrIds: string | string[]
  ): Promise<QuarantineRestoreResponse | QuarantineRestoreResponse[]> {
    const body = Array.isArray(quarantineIdOrIds)
      ? { quarantine_ids: quarantineIdOrIds }
      : { quarantine_id: quarantineIdOrIds };
    return this.request<QuarantineRestoreResponse | QuarantineRestoreResponse[]>(
      'restore',
      {
        method: 'POST',
        body
      }
    );
  }

  async batchFileOperation(operation: 'delete' | 'quarantine', files: { file_path: string }[]): Promise<BatchOperationResponse> {
    return this.request<BatchOperationResponse>('batch-actions', {
      method: 'POST',
      body: { operation, files }
    });
  }

  // Delete a single file
  async deleteFile(filePath: string): Promise<{ success: boolean }> {
    return this.request<{ success: boolean }>('delete', {
      method: 'POST',
      body: { 
        file_path: filePath
      }
    });
  }

  /**
   * Get activity logs with filtering support
   * @param filters Optional filters for the activity logs (start date, end date, event type, severity, etc.)
   * @returns Activity log data with items, pagination info, settings, and available filters
   */
  /**
   * Get uptime information from the WordPress site
   * @returns Uptime data including status, response time, WP version, and system health metrics
   */
  async getUptime(): Promise<{
    success: boolean;
    data: {
      status: string;
      timestamp: number;
      response_time: number;
      wp_version: string;
      wpsec_version: string;
      maintenance_mode: boolean;
      database: {
        connected: boolean;
        error: string | null;
      };
      memory: {
        usage_percent: number;
        critical: boolean;
      };
      filesystem: {
        accessible: boolean;
      };
      has_fatal_errors: boolean;
      plugin_status: boolean;
    };
  }> {
    return this.request('uptime');
  }

  async getActivityLogs(filters: {
    start?: string;         // Start date (YYYY-MM-DD)
    end?: string;           // End date (YYYY-MM-DD)
    severity?: string;      // Severity level (info, warning, critical)
    event_type?: string;    // Event type (login_attempt, role_change, etc.)
    user_id?: number;       // User ID
    username?: string;      // Username
    ip_address?: string;    // IP address
    object_type?: string;   // Object type (post, user, plugin, theme, etc.)
    object_id?: string;     // Object ID
    per_page?: number;      // Number of logs per page
    page?: number;          // Page number
    orderby?: string;       // Field to order by
    order?: 'ASC' | 'DESC'; // Sort direction
  } = {}): Promise<{
    data: {
      items: any[];
      total: number;
      page: number;
      pages: number;
      settings: any;
      available_filters: {
        start: string;
        end: string;
        severity: string[];
        event_type: string[];
        user_id: number[];
        username: string[];
        ip_address: string[];
        object_type: string[];
        object_id: string[];
        per_page: string;
        page: string;
        orderby: string[];
        order: string[];
      };
    };
  }> {
    // Build the URL with wpsec_endpoint and all filters as query parameters
    // Build the URL with wpsec_endpoint and all filters as top-level query parameters
    const baseUrl = this.domain.startsWith('http') ? this.domain : `https://${this.domain}`;
    const url = new URL(baseUrl);
    url.searchParams.append('wpsec_endpoint', 'activity-log');
    Object.entries(filters).forEach(([key, value]) => {
      if (value !== undefined) {
        url.searchParams.append(key, String(value));
      }
    });
    const fetchFn = await initFetch();
    const response = await fetchFn(url.toString(), {
      headers: {
        'x-api-key': this.apiKey,
        'Content-Type': 'application/json'
      },
      method: 'GET'
    });
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`WPSec API error: ${response.statusText} - ${errorText}`);
    }
    return response.json();
  }
}
