# Scan Detections Pagination Implementation Guide

## API Endpoint Overview

The WPFort server implements pagination for the scan detections endpoint:

```
GET /:domain/detections
```

## Pagination Parameters

The API accepts the following query parameters for pagination:

| Parameter | Type    | Default | Description                                |
|-----------|---------|--------|--------------------------------------------|
| limit     | integer | 100    | Number of items to return per page         |
| offset    | integer | 0      | Number of items to skip before starting    |
| status    | string  | null   | Optional filter for detection status       |
| scan_id   | string  | null   | Optional filter for specific scan          |

## Example Request

```
GET /example.com/detections?limit=50&offset=0
```

## Response Format

The API returns a JSON response with the following structure:

```json
{
  "status": "success",
  "detections": [
    {
      "id": "uuid-string",
      "website_id": "uuid-string",
      "scan_id": "string",
      "file_path": "string",
      "threat_score": "number",
      "confidence": "number",
      "detection_type": ["string"],
      "severity": "string",
      "description": "string",
      "file_hash": "string",
      "file_size": "number",
      "context_type": "string",
      "risk_level": "string",
      "version_number": "number",
      "created_at": "timestamp",
      "status": "string",
      "website_scan_id": "string",
      "scan_started_at": "timestamp",
      "scan_completed_at": "timestamp",
      "scan_status": "string",
      "quarantine_info": {
        "id": "uuid-string",
        "quarantine_id": "string",
        "original_path": "string",
        "quarantine_path": "string",
        "timestamp": "timestamp",
        "file_size": "number",
        "file_type": "string",
        "file_hash": "string"
      },
      "deletion_info": {
        "id": "uuid-string",
        "timestamp": "timestamp"
      }
    }
    // ... more detection objects
  ],
  "pagination": {
    "total": 235,
    "limit": 50,
    "offset": 0,
    "has_more": true
  }
}
```

## Pagination Metadata

The `pagination` object in the response contains:

- `total`: Total number of detections matching the query (across all pages)
- `limit`: Number of items per page (same as request parameter)
- `offset`: Current offset (same as request parameter)
- `has_more`: Boolean indicating if there are more pages available

## Frontend Implementation Guidelines

### 1. Initial Data Loading

When the detections page loads, make an initial request with default pagination:

```typescript
// Example using fetch API
const fetchDetections = async (domain, limit = 100, offset = 0, filters = {}) => {
  const queryParams = new URLSearchParams({
    limit: limit.toString(),
    offset: offset.toString(),
    ...filters
  });
  
  const response = await fetch(`/api/${domain}/detections?${queryParams}`);
  return await response.json();
};

// Initial load
const initialData = await fetchDetections('example.com');
```

### 2. Implementing Pagination Controls

Create UI components for pagination:

```tsx
// React example
const DetectionsPage = () => {
  const [detections, setDetections] = useState([]);
  const [pagination, setPagination] = useState({
    total: 0,
    limit: 100,
    offset: 0,
    has_more: false
  });
  
  // Load data function
  const loadData = async (newOffset) => {
    const data = await fetchDetections('example.com', pagination.limit, newOffset);
    setDetections(data.detections);
    setPagination(data.pagination);
  };
  
  // Handle page change
  const handlePageChange = (newPage) => {
    const newOffset = (newPage - 1) * pagination.limit;
    loadData(newOffset);
  };
  
  // Calculate total pages
  const totalPages = Math.ceil(pagination.total / pagination.limit);
  const currentPage = Math.floor(pagination.offset / pagination.limit) + 1;
  
  return (
    <div>
      {/* Detections list rendering */}
      <div className="detections-list">
        {detections.map(detection => (
          <DetectionItem key={detection.id} detection={detection} />
        ))}
      </div>
      
      {/* Pagination controls */}
      <div className="pagination-controls">
        <button 
          disabled={currentPage === 1}
          onClick={() => handlePageChange(currentPage - 1)}
        >
          Previous
        </button>
        
        <span>Page {currentPage} of {totalPages}</span>
        
        <button 
          disabled={!pagination.has_more}
          onClick={() => handlePageChange(currentPage + 1)}
        >
          Next
        </button>
      </div>
    </div>
  );
};
```

### 3. Implementing Page Size Controls

Allow users to change the number of items per page:

```tsx
const PageSizeSelector = ({ value, onChange }) => {
  return (
    <select 
      value={value} 
      onChange={(e) => onChange(parseInt(e.target.value))}
    >
      <option value="25">25 per page</option>
      <option value="50">50 per page</option>
      <option value="100">100 per page</option>
      <option value="250">250 per page</option>
    </select>
  );
};

// In the main component:
const handlePageSizeChange = (newLimit) => {
  // Reset to first page when changing page size
  loadData(0, newLimit);
};

// Then in the JSX:
<PageSizeSelector 
  value={pagination.limit} 
  onChange={handlePageSizeChange} 
/>
```

### 4. Handling Filters

When applying filters, reset pagination to the first page:

```typescript
const applyFilters = (filters) => {
  // Reset to first page when applying filters
  const data = await fetchDetections('example.com', pagination.limit, 0, filters);
  setDetections(data.detections);
  setPagination(data.pagination);
};
```

### 5. Important Notes

1. **UUID Handling**: Note that the `website_id` field is a UUID type, not an integer. Ensure proper UUID handling in your frontend code.

2. **Loading States**: Implement loading indicators during pagination operations to improve user experience.

3. **Error Handling**: Add proper error handling for API requests:

```typescript
try {
  const data = await fetchDetections(...);
  // Handle success
} catch (error) {
  // Show error message to user
  console.error('Failed to fetch detections:', error);
}
```

4. **Caching Considerations**: Consider caching previously loaded pages to reduce API calls when users navigate back to a previously viewed page.

5. **URL Synchronization**: Consider updating the URL with the current pagination state to allow for bookmarking and sharing specific pages.
