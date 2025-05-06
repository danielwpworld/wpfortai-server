# WPFort Firewall API Instructions

This document provides simple instructions for using the WPFort Firewall APIs to manage IP whitelisting and blocking.

## 1. Whitelist an IP Address

Allow specific IPs to bypass firewall restrictions.

- **Endpoint**: `/:domain/whitelist`
- **Method**: `POST`
- **Body**:
  ```json
  {
    "action": "add",
    "ip": "192.168.1.1"
  }
  ```
- **Output Format**:
  ```json
  {
    "success": true
  }
  ```

## 2. Remove an IP from Whitelist

Remove an IP from the whitelist to restore normal firewall restrictions.

- **Endpoint**: `/:domain/whitelist`
- **Method**: `POST`
- **Body**:
  ```json
  {
    "action": "remove",
    "ip": "192.168.1.1"
  }
  ```
- **Output Format**:
  ```json
  {
    "success": true
  }
  ```

## 3. Block an IP Address or Range

Block specific IPs or CIDR ranges from accessing the site.

- **Endpoint**: `/:domain/blocklist`
- **Method**: `POST`
- **Body**:
  ```json
  {
    "action": "block",
    "ip": "58.49.90.146"
  }
  ```
- **Output Format**:
  ```json
  {
    "success": true
  }
  ```

## 4. Unblock an IP Address or Range

Remove an IP or CIDR range from the blocklist.

- **Endpoint**: `/:domain/blocklist`
- **Method**: `POST`
- **Body**:
  ```json
  {
    "action": "unblock",
    "ip": "58.49.90.146"
  }
  ```
- **Output Format**:
  ```json
  {
    "success": true
  }
  ```

## Notes

- Replace `:domain` in the endpoint with your actual domain (e.g., `example.com/whitelist`)
- You can use CIDR notation for IP ranges (e.g., `192.168.1.0/24`)
- All requests require proper authentication via the `x-wpfort-token` header
- Error responses will have the format: `{ "error": "Error message" }`


## The current whitelist / blocklist is within the firewall status response.

- **Endpoint**: `/:domain/status`
- **Method**: `GET`
- **Output Format**:
  ```json
{
    "active": "1",
    "whitelisted_ips": [
        "192.168.1.100"
    ],
    "blocklisted_ips": [
        "58.49.90.146"
    ],
    "stats": {
        "total_blocked": "0",
        "recent_blocks": [
            {
                "timestamp": "2025-05-06 16:27:34",
                "ip": "38.242.138.32",
                "country": "Germany",
                "request_uri": "/wp-cron.php?doing_wp_cron=1746548853.5332269668579101562500",
                "rules": [
                    {
                        "rule": "sql_injection",
                        "description": "SQL Injection attempt",
                        "score": 5,
                        "matched_data": "{\"header_accept\":\"*\\/*\"}"
                    },
                    {
                        "rule": "sql_injection",
                        "description": "SQL Injection attempt",
                        "score": 5,
                        "matched_data": "{\"header_user-agent\":\"WordPress\\/6.8.1; https:\\/\\/sub2.test-wpworld.uk\"}"
                    },
                    {
                        "rule": "file_upload",
                        "description": "Malicious file upload attempt",
                        "score": 5,
                        "matched_data": "{\"request_uri\":\"\\/wp-cron.php?doing_wp_cron=1746548853.5332269668579101562500\"}"
                    },
                    {
                        "rule": "file_upload",
                        "description": "Malicious file upload attempt",
                        "score": 5,
                        "matched_data": "{\"raw_uri\":\"\\/wp-cron.php?doing_wp_cron=1746548853.5332269668579101562500\"}"
                    }
                ],
                "is_critical": true
            },
            {
                "timestamp": "2025-05-06 16:27:33",
                "ip": "54.86.50.139",
                "country": "United States",
                "request_uri": "/?wpsec_endpoint=firewall/status",
                "rules": [
                    {
                        "rule": "sql_injection",
                        "description": "SQL Injection attempt",
                        "score": 5,
                        "matched_data": "{\"header_accept\":\"*\\/*\"}"
                    }
                ],
                "is_critical": false
            },
            {
                "timestamp": "2025-05-06 16:27:13",
                "ip": "38.242.138.32",
                "country": "Germany",
                "request_uri": "/wp-cron.php?doing_wp_cron=1746548832.5102450847625732421875",
                "rules": [
                    {
                        "rule": "sql_injection",
                        "description": "SQL Injection attempt",
                        "score": 5,
                        "matched_data": "{\"header_accept\":\"*\\/*\"}"
                    },
                    {
                        "rule": "sql_injection",
                        "description": "SQL Injection attempt",
                        "score": 5,
                        "matched_data": "{\"header_user-agent\":\"WordPress\\/6.8.1; https:\\/\\/sub2.test-wpworld.uk\"}"
                    },
                    {
                        "rule": "file_upload",
                        "description": "Malicious file upload attempt",
                        "score": 5,
                        "matched_data": "{\"request_uri\":\"\\/wp-cron.php?doing_wp_cron=1746548832.5102450847625732421875\"}"
                    },
                    {
                        "rule": "file_upload",
                        "description": "Malicious file upload attempt",
                        "score": 5,
                        "matched_data": "{\"raw_uri\":\"\\/wp-cron.php?doing_wp_cron=1746548832.5102450847625732421875\"}"
                    }
                ],
                "is_critical": true
            },
            {
                "timestamp": "2025-05-06 16:27:12",
                "ip": "54.86.50.139",
                "country": "United States",
                "request_uri": "/?wpsec_endpoint=firewall/blocklist",
                "rules": [
                    {
                        "rule": "sql_injection",
                        "description": "SQL Injection attempt",
                        "score": 5,
                        "matched_data": "{\"header_accept\":\"*\\/*\"}"
                    }
                ],
                "is_critical": false
            },
            {
                "timestamp": "2025-05-06 16:26:05",
                "ip": "62.171.130.143",
                "country": "Germany",
                "request_uri": "/wp-json/wpsec/v1/site-info",
                "rules": [
                    {
                        "rule": "sql_injection",
                        "description": "SQL Injection attempt",
                        "score": 5,
                        "matched_data": "{\"header_accept\":\"*\\/*\"}"
                    }
                ],
                "is_critical": false
            },
            {
                "timestamp": "2025-05-06 16:26:03",
                "ip": "62.171.130.143",
                "country": "Germany",
                "request_uri": "/wp-json/wpsec/v1/core-check",
                "rules": [
                    {
                        "rule": "sql_injection",
                        "description": "SQL Injection attempt",
                        "score": 5,
                        "matched_data": "{\"header_accept\":\"*\\/*\"}"
                    }
                ],
                "is_critical": false
            },
            {
                "timestamp": "2025-05-06 16:26:01",
                "ip": "62.171.130.143",
                "country": "Germany",
                "request_uri": "/wp-json/wpsec/v1/firewall/logs?period=30",
                "rules": [
                    {
                        "rule": "sql_injection",
                        "description": "SQL Injection attempt",
                        "score": 5,
                        "matched_data": "{\"header_accept\":\"*\\/*\"}"
                    }
                ],
                "is_critical": false
            },
            {
                "timestamp": "2025-05-06 16:26:01",
                "ip": "62.171.130.143",
                "country": "Germany",
                "request_uri": "/wp-json/wpsec/v1/firewall/status",
                "rules": [
                    {
                        "rule": "sql_injection",
                        "description": "SQL Injection attempt",
                        "score": 5,
                        "matched_data": "{\"header_accept\":\"*\\/*\"}"
                    }
                ],
                "is_critical": false
            },
            {
                "timestamp": "2025-05-06 16:26:01",
                "ip": "62.171.130.143",
                "country": "Germany",
                "request_uri": "/wp-json/wpsec/v1/vulnerabilities",
                "rules": [
                    {
                        "rule": "sql_injection",
                        "description": "SQL Injection attempt",
                        "score": 5,
                        "matched_data": "{\"header_accept\":\"*\\/*\"}"
                    }
                ],
                "is_critical": false
            },
            {
                "timestamp": "2025-05-06 16:26:01",
                "ip": "38.242.138.32",
                "country": "Germany",
                "request_uri": "/wp-cron.php?doing_wp_cron=1746548761.0879778861999511718750",
                "rules": [
                    {
                        "rule": "sql_injection",
                        "description": "SQL Injection attempt",
                        "score": 5,
                        "matched_data": "{\"header_accept\":\"*\\/*\"}"
                    },
                    {
                        "rule": "sql_injection",
                        "description": "SQL Injection attempt",
                        "score": 5,
                        "matched_data": "{\"header_user-agent\":\"WordPress\\/6.8.1; https:\\/\\/sub2.test-wpworld.uk\"}"
                    },
                    {
                        "rule": "file_upload",
                        "description": "Malicious file upload attempt",
                        "score": 5,
                        "matched_data": "{\"request_uri\":\"\\/wp-cron.php?doing_wp_cron=1746548761.0879778861999511718750\"}"
                    },
                    {
                        "rule": "file_upload",
                        "description": "Malicious file upload attempt",
                        "score": 5,
                        "matched_data": "{\"raw_uri\":\"\\/wp-cron.php?doing_wp_cron=1746548761.0879778861999511718750\"}"
                    }
                ],
                "is_critical": true
            }
        ],
        "top_ips": [],
        "top_rules": []
    }
}
  ```


