# API v3 Documentation

## Base URL

All endpoints in this API have the base URL: `/v3`

### Security Headers

All responses from this API include the following security headers:

- `Strict-Transport-Security`: Ensures that browsers will only connect to the
  server over HTTPS.
- `X-Content-Type-Options`: Prevents browsers from MIME-sniffing a response away
  from the declared content type.
- `Content-Security-Policy`: Helps prevent XSS attacks by restricting the
  sources of content that can be loaded on a web page.
- `Referrer-Policy`: Specifies how much referrer information should be included
  with requests.
- `Cache-Control`: Directs caches not to store the response.
- `Permissions-Policy`: Defines the permissions the site requires to function
  correctly.

## Endpoints

### Get Gateway Clients

```http
GET /v3/clients?country=cameroon&per_page=20&page=2
```

#### Description

Get gateway clients with optional filters.

#### Parameters

- `country` (optional): Filter by country.
- `operator` (optional): Filter by operator.
- `protocols` (optional): Filter by protocols.
- `page` (optional): Page number for pagination (default: 1).
- `per_page` (optional): Number of results per page (default: 10).

#### Response

```json
[
	{
		"country": "Cameroon",
		"last_published_date": 1714846064,
		"msisdn": "+xxxxxxxxx",
		"operator": "OPERATOR",
		"operator_code": "xxxxxx",
		"protocols": ["https", "smtp", "ftp"]
	}
]
```

> [!NOTE]
>
> - `last_published_date` field is in
>   [unix time](https://en.wikipedia.org/wiki/Unix_time).

#### Errors

- `400 Bad Request`: If the request is malformed.
- `500 Internal Server Error`: If an unexpected error occurs.

### Get Tests for a Gateway Client

```http
GET /v3/clients/<msisdn>/tests?per_page=20&page=2
```

#### Description

Get reliability tests for a specific gateway client with optional filters.

#### Parameters

- `page` (optional): Page number for pagination (default: 1).
- `per_page` (optional): Number of results per page (default: 10).

#### Response

```json
[
	{
		"id": 1,
		"msisdn": "+xxxxxxxxx",
		"sms_received_time": 1713995252,
		"sms_routed_time": 1713995260,
		"sms_sent_time": 1713995250,
		"start_time": 1715377980,
		"status": "success"
	}
]
```

> [!NOTE]
>
> - `sms_received_time`, `sms_routed_time`, `sms_sent_time`, and `start_time`
>   fields are in [unix time](https://en.wikipedia.org/wiki/Unix_time).
> - `status` field for the tests has two values: `"success"` or `"timedout"`.

#### Errors

- `400 Bad Request`: If the request is malformed.
- `404 Not Found`: If the requested resource is not found.
- `500 Internal Server Error`: If an unexpected error occurs.
