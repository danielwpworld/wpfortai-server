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

  private async request<T>(endpoint: string, options: Partial<Omit<RequestInit, 'body'>> & { body?: any } = {}): Promise<T> {
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



    const fetchFn = await initFetch();
  const response = await fetchFn(url.toString(), requestOptions);

    if (!response.ok) {
      throw new Error(`WPSec API error: ${response.statusText}`);
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

  async getScanResults(scanId: string): Promise<ScanResults> {
    return this.request<ScanResults>(`scan/${scanId}/results`);
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

  async getFirewallLogs(period?: number): Promise<FirewallLog[]> {
    const endpoint = period ? `firewall/logs?period=${period}` : 'firewall/logs';
    return this.request<FirewallLog[]>(endpoint);
  }

  async whitelistFirewallIP(ip: string, action: 'add' | 'remove'): Promise<void> {
    return this.request('firewall/whitelist', {
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
    return this.request<BackupStatus>(`backup/restore/${restoreId}/status`);
  }

  // WordPress Core Management
  async checkCoreIntegrity(): Promise<CoreCheckResult> {
    return this.request<CoreCheckResult>('core-check');
  }

  async updateAll(): Promise<void> {
    return this.request('update-all', {
      method: 'POST'
    });
  }

  async updateItems(type: 'plugins' | 'themes' | 'wordpress', items: string[]): Promise<void> {
    return this.request('update-items', {
      method: 'POST',
      body: { type, items }
    });
  }

  // File Management
  async whitelistFile(filePath: string, reason?: string, addedBy?: string): Promise<void> {
    return this.request('whitelist', {
      method: 'POST',
      body: {
        file_path: filePath,
        reason,
        added_by: addedBy
      }
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

  async restoreQuarantinedFile(quarantineId: string): Promise<QuarantineRestoreResponse> {
    return this.request<QuarantineRestoreResponse>('quarantine/restore', {
      method: 'POST',
      body: { quarantine_id: quarantineId }
    });
  }

  async batchFileOperation(operation: 'delete' | 'quarantine', files: { file_path: string }[]): Promise<BatchOperationResponse> {
    return this.request<BatchOperationResponse>('quarantine/batch', {
      method: 'POST',
      body: { operation, files }
    });
  }
}
