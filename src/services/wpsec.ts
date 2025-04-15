import fetch from 'node-fetch';
import { ScanStatus, ScanResults } from '../types';

export class WPSecAPI {
  private readonly baseUrl = 'https://api.wpsec.com/v1';
  private readonly apiKey: string;
  private readonly domain: string;
  private readonly websiteId: string;

  constructor(domain: string, websiteId: string) {
    this.apiKey = process.env.WPFORT_API_KEY || '';
    this.domain = domain;
    this.websiteId = websiteId;
  }

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const response = await fetch(`${this.baseUrl}${endpoint}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.apiKey}`,
        ...options.headers,
      },
    });

    if (!response.ok) {
      throw new Error(`WPSec API error: ${response.statusText}`);
    }

    return response.json() as Promise<T>;
  }

  async startScan(): Promise<{ scan_id: string }> {
    return this.request<{ scan_id: string }>('/scan', {
      method: 'POST',
    });
  }

  async getScanStatus(scanId: string): Promise<ScanStatus> {
    return this.request<ScanStatus>(`/scan-status/${scanId}`);
  }

  async getScanResults(scanId: string): Promise<ScanResults> {
    return this.request<ScanResults>(`/scan/${scanId}/results`);
  }
}
