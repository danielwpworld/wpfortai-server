import fetch, { RequestInit } from 'node-fetch';
import { ScanStore } from './scan-store';
import { ScanResults } from '../types';

export interface ScanStatus {
  scan_id: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  started_at: string;
  progress: string;
  files_scanned: string;
  total_files: string;
  results_endpoint: string;
  completed_at?: string;
  duration?: number;
}

export interface ScanStartResponse {
  status: 'success' | 'error';
  message: string;
  scan_id: string;
  started_at: string;
  estimated_duration: string;
  check_status_endpoint: string;
  results_endpoint: string;
}

export interface SiteInfo {
  domain: string;
  wpVersion: string;
  plugins: Array<{
    name: string;
    version: string;
    active: boolean;
  }>;
  themes: Array<{
    name: string;
    version: string;
    active: boolean;
  }>;
}

export interface Vulnerability {
  id: string;
  title: string;
  type: 'plugin' | 'theme' | 'wordpress';
  component: string;
  version: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  recommendation?: string;
  references?: string[];
}

export interface FirewallStatus {
  active: boolean;
  rules_count: number;
  blocked_requests: number;
  last_updated: string;
}

export interface FirewallLog {
  timestamp: string;
  ip: string;
  request_uri: string;
  rule_triggered: string;
  action_taken: string;
}

export interface BackupStatus {
  id: string;
  status: 'pending' | 'in_progress' | 'completed' | 'failed';
  type: string;
  progress?: number;
  error?: string;
  started_at: string;
  completed_at?: string;
}

export interface BackupListItem {
  id: string;
  type: string;
  size: number;
  created_at: string;
  status: string;
  download_url?: string;
}

export interface WhitelistedFile {
  file_path: string;
  reason?: string;
  added_by?: string;
  added_at: string;
  hash?: string;
  status?: 'valid' | 'modified' | 'missing';
}

export interface CoreCheckResult {
  status: 'clean' | 'modified' | 'warning';
  modified_files?: string[];
  missing_files?: string[];
  extra_files?: string[];
  wordpress_version: string;
  is_latest: boolean;
  latest_version?: string;
}

export class WPSecAPI {
  private readonly apiKey: string;
  private readonly domain: string;

  constructor(domain: string) {
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



    const response = await fetch(url.toString(), requestOptions);

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
}
