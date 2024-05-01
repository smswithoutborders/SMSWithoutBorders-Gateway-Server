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
- `protocol` (optional): Filter by protocol.
- `page` (optional): Page number for pagination (default: 1).
- `per_page` (optional): Number of results per page (default: 10).

#### Response

```json
[
	{
		"country": "Cameroon",
		"last_published_date": "Wed, 24 Apr 2024 19:43:02 GMT",
		"msisdn": "+xxxxxxxxx",
		"operator": "OPERATOR",
		"protocols": "https",
		"test_data": [
			{
				"id": 1,
				"msisdn": "+xxxxxxxxx",
				"sms_received_time": "Wed, 24 Apr 2024 22:47:32 GMT",
				"sms_routed_time": "Wed, 24 Apr 2024 22:47:40 GMT",
				"sms_sent_time": "Wed, 24 Apr 2024 22:47:30 GMT",
				"start_time": "Wed, 24 Apr 2024 22:47:28 GMT",
				"status": "success"
			},
			...
		]
	},
    ...
]
```

#### Errors

- `400 Bad Request`: If the request is malformed.
- `500 Internal Server Error`: If an unexpected error occurs.
