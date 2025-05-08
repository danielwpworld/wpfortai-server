# Update API Instructions

## Update All Items
- **Method:** POST
- **Endpoint:** `/api/update/:domain/all`
- **Body:** _(none)_

**Example:**
```
POST /api/update/sub2.test-wpworld.uk/all
Content-Type: application/json

{}
```

---

## Update Specific Items
- **Method:** POST
- **Endpoint:** `/api/update/:domain/items`
- **Body:**
```
{
  "type": "plugin", // or "theme"
  "items": [
    { "slug": "woocommerce" }
  ]
}
```

**Example:**
```
POST /api/update/sub2.test-wpworld.uk/items
Content-Type: application/json

{
  "type": "plugin",
  "items": [
    { "slug": "woocommerce" }
  ]
}
```
