
## Assessment API Guide

on our frontend we have a "fix all" button. what we want this button to do is call an api on this server, that performs an assessment of what issues currently exist on the website (using wpsec and checking scan_detections) and sends back a list of actionable items.

for example, if we the website has  scan_detections with threat score over 5 from the last scan -> add an action item "Quarantine infected files".

if the website has permissions issues or wp_core file integrity issues -> add actions items: "Fix WordPress core files integrity", "Fix WordPress file permissions".

if the firewall is off -> "Turn on firewall for enhanced security".

If the website has vulnerabilities -> "Update vulnerable plugins & themes".

## Data included with action items
WPCore layer data:
- WP Core file integrity issues (i.e list of missing / modified files (full path))
- WP Core file permissions issues (the files and their current permissions (full path))

Filesystem layer data (scan_detections):
- List of files (full path) with high threat score (over 5)
- Explain detection type (pattern, signature, etc)

Application layer (vulnerabilities) data:
- List of vulnerabilities (full path)
- Recommendation whether to update the plugin/theme

Firewall layer data:
- Firewall status

## WordPress Core Layer Data Structure

```typescript
// WordPress Core File Integrity Issues
interface WPCoreFileIntegrityIssue {
  file_path: string;         // Full path to the file
  file_status: 'modified' | 'missing' | 'unknown';  // Status of the file
  severity: 'low' | 'medium' | 'high' | 'critical'; // Severity of the issue
  type: string;              // Type of file (e.g., 'core')
}

// WordPress Core File Permissions Issues
interface WPCoreFilePermissionIssue {
  file_path: string;         // Full path to the file
  current_perms: string;     // Current permissions (e.g., '0644')
  recommended_perms: string; // Recommended permissions
  is_writable: boolean;      // Whether the file is writable
  is_readable: boolean;      // Whether the file is readable
  status: string;            // Status of the issue (e.g., 'critical', 'warning')
  issues: string[];          // List of specific issues with the file
}

// WP Core Action Item Structure
interface WPCoreActionItem {
  action: string;            // The action to be taken (e.g., "Fix WordPress core files integrity", "Fix WordPress file permissions")
  risk_score: number;        // Risk score (0-10) assigned by AI middleware
  data: {
    wp_core_file_integrity_issues?: WPCoreFileIntegrityIssue[];
    wp_core_file_permission_issues?: WPCoreFilePermissionIssue[];
  };
}
```



## Filesystem Layer Data Structure

```typescript
// Scan Detection for Infected Files
interface ScanDetection {
  file_path: string;         // Full path to the file
  threat_score: number;      // Threat score (0-10)
  detection_type: string[];  // Type of detection (e.g., 'anomaly', 'signature', 'pattern')
  severity: string;          // Severity level (e.g., 'low', 'medium', 'high', 'critical')
  description: string;       // Description of the detection
  file_hash?: string;        // Hash of the file (if available)
  file_size: number;         // Size of the file in bytes
  context_type: string;      // Context of the file (e.g., 'plugin', 'theme', 'core')
  risk_level: string;        // Risk level assessment
  status: string;            // Current status of the detection (e.g., 'active', 'quarantined')
}

// Quarantine Infected Files Action Item
interface QuarantineActionItem {
  action: string;            // The action to be taken (e.g., "Quarantine infected files")
  risk_score: number;        // Risk score (0-10) assigned by AI middleware
  data: {
    scan_detections: ScanDetection[]; // List of infected files with high threat scores (> 5)
  };
}
```

## Required API Endpoints and Functions

### WP Core Layer Data Retrieval

```typescript
// Function to retrieve WordPress core integrity and permissions data
async function getWPCoreData(domain: string): Promise<CoreCheckResult> {
  // Create WPSec API instance
  const api = new WPSecAPI(domain);
  
  // Call the checkCoreIntegrity method to get core file integrity and permissions data
  return await api.checkCoreIntegrity();
  
  // This will return a CoreCheckResult object containing:
  // - modified_files: Array of files that have been modified
  // - missing_files: Array of files that are missing
  // - permissions: Object containing directories and files with permission issues
}
```

### Scan Detections Retrieval

```typescript
// Function to retrieve scan detections with high threat scores
async function getHighThreatDetections(websiteId: string): Promise<ScanDetection[]> {
  // Query the database for scan detections with threat_score > 5
  const query = `
    SELECT * FROM scan_detections 
    WHERE website_id = $1 AND threat_score > 5 AND status = 'active'
    ORDER BY threat_score DESC
  `;
  
  const result = await pool.query(query, [websiteId]);
  return result.rows;
}

// Function to retrieve the latest scan results
async function getLatestScanResults(domain: string, scanId?: string): Promise<ScanResults> {
  // Create WPSec API instance
  const api = new WPSecAPI(domain);
  
  // Get scan results from WPSec API
  return await api.getScanResults(scanId);
}
```

## Application Layer (Vulnerabilities) Data Structure

```typescript
// Vulnerability Item
interface Vulnerability {
  id: string;               // Unique identifier for the vulnerability
  title: string;            // Title/name of the vulnerability
  type: 'plugin' | 'theme' | 'wordpress'; // Type of component affected
  component: string;        // Name of the affected component (plugin/theme name)
  version: string;          // Current version with the vulnerability
  severity: 'low' | 'medium' | 'high' | 'critical'; // Severity level
  description: string;      // Description of the vulnerability
  recommendation?: string;  // Recommended action to fix the vulnerability
  references?: string[];    // References to CVEs or other documentation
}

// Update Vulnerable Plugins & Themes Action Item
interface UpdateVulnerabilitiesActionItem {
  action: string;           // The action to be taken (e.g., "Update vulnerable plugins & themes")
  risk_score: number;       // Risk score (0-10) assigned by AI middleware
  data: {
    vulnerabilities: Vulnerability[]; // List of vulnerabilities found on the website
  };
}
```

### Retrieving Vulnerability Data

```typescript
// Function to retrieve vulnerabilities for a website
async function getVulnerabilities(domain: string): Promise<Vulnerability[]> {
  // Create WPSec API instance
  const api = new WPSecAPI(domain);
  
  // Get vulnerabilities from WPSec API
  return await api.getVulnerabilities();
}

// Function to update all components (plugins, themes, core)
async function updateAllComponents(domain: string): Promise<void> {
  // Create WPSec API instance
  const api = new WPSecAPI(domain);
  
  // Create a record for this update operation
  const updateId = await UpdateStore.createUpdate(domain, websiteId);
  
  // Update all components
  await api.updateAll(updateId);
}
```

## Firewall Layer Data Structure

```typescript
// Firewall Status
interface FirewallStatus {
  active: boolean;          // Whether the firewall is active or not
  rules_count: number;      // Number of firewall rules
  blocked_requests: number; // Number of blocked requests
  last_updated: string;     // Last update timestamp
}

// Firewall Action Item
interface FirewallActionItem {
  action: string;           // The action to be taken (e.g., "Turn on firewall for enhanced security")
  risk_score: number;       // Always 1 for firewall actions
  data: {
    firewall_status: FirewallStatus; // Current status of the firewall
  };
}
```

### Retrieving Firewall Status

```typescript
// Function to retrieve firewall status for a website
async function getFirewallStatus(domain: string): Promise<FirewallStatus> {
  // Create WPSec API instance
  const api = new WPSecAPI(domain);
  
  // Get firewall status from WPSec API
  return await api.getFirewallStatus();
}

// Function to toggle firewall status
async function toggleFirewall(domain: string, active: boolean): Promise<void> {
  // Create WPSec API instance
  const api = new WPSecAPI(domain);
  
  // Toggle firewall status
  await api.toggleFirewall(active);
}
```


## Ai middleware to assess the risk score for each action item

we will pass the action items & their data (full json object) to the AI middleware, and the AI middleware will set a risk score (0-10) for each action item, based on the data provided. The AI middleware will return the action items sorted by risk score, with the highest risk items first.
AI could include a little description for each action item, explaining why it has that risk score.

## Ai middleware response structure

```typescript
interface AiMiddlewareResponse {
  action_items: ActionItem[];
}

interface ActionItem {
  action: string;
  risk_score: number;
  data: any;
  description: string;
}
```

## Asynchronous Assessment Architecture

Since the assessment process involves multiple API calls and potentially time-consuming AI processing, an asynchronous architecture is required:

1. **Initial Request Handling**:
   - The `/:domain/assessment` endpoint immediately returns an assessment ID and status
   - Generate a unique ID with format `assess_[20 random characters]`
   - Store initial data in Redis with status "pending"

2. **Worker Processing**:
   - A worker picks up the pending assessment
   - Gathers data from multiple sources (WP Core, scan detections, vulnerabilities, firewall)
   - Sends the collected data to the AI middleware for risk scoring
   - Updates the Redis entry with status "completed" and the results

3. **Status Checking**:
   - Add a `/:domain/assessment/:assessmentId/status` endpoint for clients to check progress
   - Return current status and results if available

### API Response Formats

#### 1. Creating a New Assessment (Success)

```json
{
  "status": "success",
  "assessment_id": "assess_d67300fd2cba4d09316d",
  "message": "Assessment initiated successfully"
}
```

#### 2. Existing Assessment Job (409 Conflict)

```json
{
  "status": "error",
  "message": "An assessment is already in progress for this domain",
  "assessment_id": "assess_d67300fd2cba4d09316d",
  "assessment_status": "pending"
}
```

#### 3. Checking Assessment Status (Pending)

```json
{
  "status": "success",
  "assessment_id": "assess_d67300fd2cba4d09316d",
  "assessment_status": "pending",
  "started_at": "2025-05-30T07:42:18.349Z"
}
```

#### 4. Checking Assessment Status (Completed)

```json
{
  "status": "success",
  "assessment_id": "assess_d67300fd2cba4d09316d",
  "assessment_status": "completed",
  "started_at": "2025-05-30T07:42:18.349Z",
  "completed_at": "2025-05-30T07:42:28.123Z",
  "results": {
    "action_items": [
      {
        "action": "Quarantine infected files",
        "risk_score": 10,
        "data": {
          "scan_detections": [
            {
              "file_path": "/wp-content/plugins/woocommerce/assets/js/jquery-blockui.js",
              "threat_score": 6,
              "detection_type": ["pattern"],
              "severity": "high",
              "description": "Malicious code detected"
            }
          ]
        },
        "description": "High-risk malware detected in plugin files"
      },
      {
        "action": "Fix WordPress core files integrity",
        "risk_score": 8,
        "data": {
          "wp_core_file_integrity_issues": [
            {
              "file_path": "/wp-includes/version.php",
              "file_status": "modified",
              "severity": "high"
            }
          ]
        },
        "description": "Critical WordPress core files have been modified"
      }
    ]
  }
}
```

#### 5. Checking Active Assessment (Not Found)

```json
{
  "status": "not_found",
  "message": "No active assessment found for this domain"
}
```

### Redis Data Structure

```typescript
interface AssessmentRedisEntry {
  assessment_id: string;      // Unique ID (assess_[20chars])
  website_id: string;         // UUID of the website
  domain: string;             // Domain of the website
  status: 'pending' | 'processing' | 'completed' | 'failed';
  started_at: string;         // ISO timestamp
  completed_at?: string;      // ISO timestamp when completed
  error?: string;             // Error message if failed
  results?: AiMiddlewareResponse; // Results from AI middleware
}
```

### Assessment Store Service

```typescript
// Similar to ScanStore or UpdateStore
export class AssessmentStore {
  private static readonly prefix = 'assessment:';
  
  // Create a new assessment
  static async createAssessment(domain: string, websiteId: string): Promise<string> {
    const assessmentId = `assess_${generateRandomString(20)}`;
    const key = `${this.prefix}${assessmentId}`;
    
    const data: AssessmentRedisEntry = {
      assessment_id: assessmentId,
      website_id: websiteId,
      domain,
      status: 'pending',
      started_at: new Date().toISOString()
    };
    
    await redisClient.set(key, JSON.stringify(data));
    return assessmentId;
  }
  
  // Get assessment by ID
  static async getAssessment(assessmentId: string): Promise<AssessmentRedisEntry | null> {
    const key = `${this.prefix}${assessmentId}`;
    const data = await redisClient.get(key);
    
    if (!data) return null;
    return JSON.parse(data) as AssessmentRedisEntry;
  }
  
  // Update assessment status
  static async updateStatus(assessmentId: string, status: AssessmentRedisEntry['status'], results?: AiMiddlewareResponse, error?: string): Promise<void> {
    const key = `${this.prefix}${assessmentId}`;
    const data = await this.getAssessment(assessmentId);
    
    if (!data) throw new Error(`Assessment ${assessmentId} not found`);
    
    const updatedData: AssessmentRedisEntry = {
      ...data,
      status,
      ...(status === 'completed' || status === 'failed' ? { completed_at: new Date().toISOString() } : {}),
      ...(results ? { results } : {}),
      ...(error ? { error } : {})
    };
    
    await redisClient.set(key, JSON.stringify(updatedData));
  }
}
```
