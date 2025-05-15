export interface Detection {
  type: 'anomaly' | 'signature' | string | string[];
  name: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number;
  description: string;
  file_hash?: string;
  match?: string;
  threat_score?: number;
  hash_type?: string;
  file_size?: number;
}

export interface FileContext {
  type: 'plugin' | 'theme' | 'unknown';
  is_core: boolean;
  is_plugin: boolean;
  is_theme: boolean;
  is_upload: boolean;
  has_plugin_header: boolean;
  has_theme_header: boolean;
  risk_level: 'low' | 'medium' | 'high';
  is_known_safe_plugin: boolean;
}

export interface InfectedFile {
  file_path: string;
  threat_score: number;
  confidence: number;
  detections: Detection[];
  context: FileContext;
  scan_time: number;
  file_size: number;
  extension: string;
}

export interface ScanResults {
  status: 'completed' | 'failed';
  scan_id: string;
  started_at: string;
  infected_files: InfectedFile[];
  total_files_scanned: string;
  infected_count: string;
  completed_at: string;
  duration: string;
}

export interface ScanStatus {
  scan_id?: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  started_at?: string;
  progress?: number;
  files_scanned?: string;
  total_files?: string;
  results_endpoint?: string;
  completed_at?: string;
  duration?: number;
  error?: string;
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
  wordpress: {
    version: string;
    site_url: string;
    domain: string;
    is_multisite: boolean;
    is_ssl: boolean;
    auth_code: string;
  };
  themes: {
    active_theme: {
      name: string;
      version: string;
    };
    total_count: number;
  };
  plugins: {
    total_count: number;
    active_count: number;
  };
  server: {
    php_version: string;
    server_software: string;
    database_version: string;
    memory_limit: string;
    wp_memory_limit: string;
  };
  timestamp: string;
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

export interface QuarantinedFile {
  quarantine_id: string;
  original_path: string;
  quarantine_path: string;
  timestamp: string;
  scan_finding_id: string | null;
  file_size: number;
  file_type: string;
  file_hash: string | null;
  detection_type: string | string[];
}

export interface QuarantineListResponse {
  status: 'success' | 'error';
  count: number;
  files: QuarantinedFile[];
}

export interface QuarantineResponse {
  status: 'success' | 'error';
  message: string;
  file_path: string;
  quarantine_id: string;
  original_path: string;
  quarantine_path: string;
  timestamp: string;
  file_size?: number;
  file_type?: string;
  file_hash?: string | null;
  detection_type?: string | string[];
}

export interface QuarantineRestoreResponse {
  status: 'success' | 'error';
  message: string;
  quarantine_id: string;
  original_path: string;
  timestamp: string;
}

export interface BatchOperationResult {
  file_path: string;
  result: QuarantinedFile | boolean;
  scan_finding_id: string;
}

export interface BatchOperationResponse {
  status: 'success' | 'error';
  message: string;
  results: {
    success: BatchOperationResult[];
    failed: BatchOperationResult[];
    total: number;
  };
}

export interface CoreCheckResult {
  status: 'success' | 'error';
  timestamp: string;
  wordpress: {
    current_version: string;
    latest_version: string;
    update_required: boolean;
  };
  php: {
    current_version: string;
    minimum_recommended: string;
    upgrade_recommended: boolean;
  };
  core_files: {
    modified_files: Array<{
      path: string;
      type: string;
      severity: string;
    }>;
    missing_files: Array<{
      path: string;
      type: string;
      severity: string;
    }>;
    unknown_files: Array<{
      path: string;
      type: string;
      severity: string;
    }>;
    summary: {
      total_checked: number;
      modified_count: number;
      missing_count: number;
      unknown_count: number;
      permission_issues: number;
    };
    checksum_api_status: {
      status: string;
      message: string;
    };
  };
  permissions: {
    directories: Record<string, {
      path: string;
      current_perms: string;
      recommended_perms: string;
      is_writable: boolean;
      is_readable: boolean;
      status: string;
      issues: string[];
    }>;
    files: Record<string, {
      path: string;
      current_perms?: string;
      recommended_perms?: string;
      is_writable?: boolean;
      is_readable?: boolean;
      status: string;
      issues?: string[];
      message?: string;
    }>;
    summary: {
      total_issues: number;
      critical_issues: number;
      warnings: number;
    };
    server_info: {
      type: string;
      is_apache: boolean;
      is_nginx: boolean;
      is_litespeed: boolean;
      is_iis: boolean;
    };
  };
}

export interface WhitelistVerificationResult {
  status: string;
  modified: string[];
  missing: string[];
}

export interface BackupStartResponse {
  backup_id: string;
  status: 'success' | 'error';
  message: string;
}

export interface BackupList {
  backups: BackupListItem[];
  total: number;
}

export interface RestoreResponse {
  restore_id: string;
  status: 'success' | 'error';
  message: string;
}

export interface RestoreStatus {
  status: 'pending' | 'in_progress' | 'completed' | 'failed';
  progress?: number;
  error?: string;
  restore_id: string;
  started_at: string;
  completed_at?: string;
}

export interface CoreIntegrityResult {
  status: 'success' | 'error';
  message: string;
  modified_files: string[];
  missing_files: string[];
  total_files_checked: number;
  integrity_status: 'ok' | 'compromised';
  last_check: string;
}
