# Activity Log API Instructions

This document describes how to use the activity log route for retrieving activity logs for a specific website domain.

## Endpoint

```
GET /api/sites/:domain/activity-log
```

- `:domain` — The domain of the website for which you want to retrieve activity logs.

## Query Parameters
The following optional query parameters can be used to filter and paginate the activity logs:

| Parameter     | Type     | Description                                                      |
|--------------|----------|------------------------------------------------------------------|
| `start`      | string   | Start date (YYYY-MM-DD) for filtering logs                        |
| `end`        | string   | End date (YYYY-MM-DD) for filtering logs                          |
| `severity`   | string   | Severity level (e.g., info, warning, critical)                    |
| `event_type` | string   | Event type (e.g., login_attempt, role_change, etc.)               |
| `user_id`    | number   | Filter by user ID                                                 |
| `username`   | string   | Filter by username                                                |
| `object_type`| string   | Type of object involved (e.g., post, user, plugin, theme, etc.)   |
| `object_id`  | string   | ID of the object involved                                         |
| `per_page`   | number   | Number of logs per page (default: 20)                             |
| `page`       | number   | Page number (default: 1)                                          |
| `orderby`    | string   | Field to order by (default: date/time)                            |
| `order`      | string   | Sort direction (`asc` or `desc`, default: `desc`)                 |

## Example Request

```
GET /api/sites/example.com/activity-log?start=2025-05-01&end=2025-05-09&event_type=login_attempt&per_page=10&page=2
```

## Example Response

```
{
  "items": [
    {
      "id": 123,
      "timestamp": "2025-05-08T15:00:00Z",
      "event_type": "login_attempt",
      "severity": "info",
      "user_id": 45,
      "username": "admin",
      "object_type": "user",
      "object_id": "45",
      "description": "User admin attempted to log in."
    },
    ...
  ],
  "total": 200,
  "page": 2,
  "pages": 20
}
```

## Error Handling
- If the domain does not exist or an error occurs, the API will return a 500 status code with an error message.

## Logging
- Successful retrievals and errors are logged for traceability.

## Notes
- You can combine multiple filters in a single request.
- Pagination is supported via `per_page` and `page`.
- The available event types and severity levels may vary depending on your installation.
