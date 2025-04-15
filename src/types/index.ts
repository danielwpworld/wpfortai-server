export interface ScanStatus {
  status: 'pending' | 'in_progress' | 'completed' | 'failed';
  progress?: number;
  error?: string;
}

export interface ScanResults {
  id: string;
  status: string;
  startedAt: string;
  completedAt?: string;
  results: {
    vulnerabilities: Array<{
      id: string;
      title: string;
      description: string;
      severity: 'low' | 'medium' | 'high' | 'critical';
      type: string;
      affectedComponent?: string;
      remediation?: string;
    }>;
    performance?: {
      score: number;
      metrics: Record<string, number>;
    };
    security?: {
      score: number;
      findings: Array<{
        type: string;
        description: string;
        severity: string;
      }>;
    };
  };
}
