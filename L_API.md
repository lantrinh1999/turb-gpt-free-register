# L Take-Number API Documentation

Only the two endpoints the client needs: get a number and get a verification code. `service` and `country` are configured by the client itself.

## Basic information

- API base URL:`http://localhost:8788`
- Request and response format:`application/json`
- Admin endpoints require authorization:

```http
Authorization: Bearer <ADMIN_AUTH_CODE>
Content-Type: application/json
```

## 1. Get a number

```http
POST /api/admin/l/take-phone
```

Request parameters:

```json
{
  "service": "facebook",
  "country": "10",
  "maxPrice": "0.05"
}
```

Field description:

| Field | Required | Description |
| --- | --- | --- |
| `service` | Yes | Project code, configured by the client itself |
| `country` | Yes | Country ID, configured by the client itself |
| `maxPrice` | No | Maximum acceptable price |

Request example:

```sh
curl -s "http://localhost:8788/api/admin/l/take-phone" \
  -H "Authorization: Bearer <ADMIN_AUTH_CODE>" \
  -H "Content-Type: application/json" \
  -d '{"service":"facebook","country":"10","maxPrice":"0.05"}'
```

Success response:

```json
{
  "item": {
    "id": "f1b8b315-8c2a-4e23-8a94-fd1c2e4a9d35",
    "activationId": "67908f935ab3410bd4c7f757",
    "service": "facebook",
    "country": "10",
    "countryName": "",
    "price": "",
    "phone": "9091234661",
    "status": "active",
    "lastCode": "",
    "createdAt": "2026-06-29T03:30:00.000Z"
  },
  "raw": "ACCESS_NUMBER:67908f935ab3410bd4c7f757:9091234661"
}
```

The client needs to save:

| Field | Purpose |
| --- | --- |
| `item.id` | Used when calling the admin get-verification-code endpoint |
| `item.phone` | The phone number obtained |

Common errors:

```json
{"error":"Please select a service"}
{"error":"Please select a country"}
{"error":"Failed to get a number: no numbers available","raw":"NO_NUMBERS"}
{"error":"Failed to get a number: insufficient balance","raw":"NO_BALANCE"}
```

## 2. Get verification code

```http
POST /api/admin/l/fetch-code
```

Request parameters:

```json
{
  "id": "f1b8b315-8c2a-4e23-8a94-fd1c2e4a9d35"
}
```

Request example:

```sh
curl -s "http://localhost:8788/api/admin/l/fetch-code" \
  -H "Authorization: Bearer <ADMIN_AUTH_CODE>" \
  -H "Content-Type: application/json" \
  -d '{"id":"f1b8b315-8c2a-4e23-8a94-fd1c2e4a9d35"}'
```

Success response:

```json
{
  "item": {
    "id": "f1b8b315-8c2a-4e23-8a94-fd1c2e4a9d35",
    "phone": "9091234661",
    "status": "code_received",
    "lastCode": "899201"
  },
  "code": "899201",
  "message": "L verification code obtained successfully",
  "raw": "STATUS_OK:899201",
  "fetchedAt": "2026-06-29T03:32:00.000Z"
}
```

Verification code not received yet:

```json
{
  "item": {
    "id": "f1b8b315-8c2a-4e23-8a94-fd1c2e4a9d35",
    "phone": "9091234661",
    "status": "active"
  },
  "code": "",
  "message": "Waiting for verification code",
  "raw": "STATUS_WAIT_CODE",
  "fetchedAt": "2026-06-29T03:32:00.000Z"
}
```

Common errors:

```json
{"error":"Missing number ID"}
{"error":"Number does not exist"}
{"error":"Number has been released, cannot get verification code"}
```
## 3. Release a number

```http
POST /api/admin/l/release
```

Used to cancel/release an acquired L number. After release, the number status becomes `released`, and its code can no longer be fetched through the get-verification-code endpoint.

The request parameters support releasing a single number:

```json
{
  "id": "f1b8b315-8c2a-4e23-8a94-fd1c2e4a9d35"
}
```

Batch release of numbers is also supported:

```json
{
  "ids": [
    "f1b8b315-8c2a-4e23-8a94-fd1c2e4a9d35",
    "8d3c6f37-4d77-4c8c-b3df-2b0d6f4f9a11"
  ]
}
```

Field description:

| Field | Required | Description |
| --- | --- | --- |
| `id` | No | Single number ID, i.e. the value returned by the get-number endpoint: `item.id` |
| `ids` | No | Array of number IDs for batch release; at least one of `id` and `ids` must be passed |

Request example:

```sh
curl -s "http://localhost:8788/api/admin/l/release" \
  -H "Authorization: Bearer <ADMIN_AUTH_CODE>" \
  -H "Content-Type: application/json" \
  -d '{"id":"f1b8b315-8c2a-4e23-8a94-fd1c2e4a9d35"}'
```

Success response:

```json
{
  "updated": 1,
  "released": 1,
  "failed": []
}
```

Partial failure response example:

```json
{
  "updated": 1,
  "released": 1,
  "failed": [
    {
      "id": "8d3c6f37-4d77-4c8c-b3df-2b0d6f4f9a11",
      "phone": "9091234662",
      "activationId": "67908f935ab3410bd4c7f758",
      "message": "Order does not exist or has expired",
      "raw": "NO_ACTIVATION"
    }
  ]
}
```

Response field description:

| Field | Description |
| --- | --- |
| `updated` | Number of numbers successfully updated to released this time; releasing an already released number again also counts as success |
| `released` | Same as `updated`, kept for compatibility with the frontend release count display |
| `failed` | List of numbers that failed to release; an empty array means all succeeded |

Common errors:

```json
{"error":"Please select a number"}
{"error":"Please configure LikeSim API Key"}
{"error":"Number not found"}
```