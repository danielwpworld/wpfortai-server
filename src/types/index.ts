export interface ScanStatus {
  scan_id: string;
  status: 'scanning' | 'completed' | 'failed';
  progress: number;
  files_scanned: number;
  total_files: number;
}

export interface ScanResults {
  scan_id: string;
  status: 'completed';
  files: {
    path: string;
    detections: Array<{
      type: 'anomaly' | 'signature' | 'heuristic';
      name: string;
      description: string;
      severity: 'critical' | 'high' | 'medium' | 'low';
      confidence: number;
    }>;
  }[];
  summary: {
    total_files: number;
    files_with_threats: number;
    total_threats: number;
    critical_threats: number;
    high_threats: number;
    medium_threats: number;
    low_threats: number;
  };
}

export interface ActiveScan {
  domain: string;
  websiteId: string;
  scanId: string;
  status: 'scanning' | 'completed' | 'failed';
  startedAt: string;
  completedAt?: string;
}
