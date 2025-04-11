# SQLCAP - Body Injection Mode

## Using the Body Injection Feature

The scanner now supports injecting SQL payloads directly into request body fields, which is crucial for testing APIs and endpoints that primarily use JSON bodies.

### Command line usage

```bash
# Basic usage for body injection mode
sqlcap --url "https://api.example.com/users" \
       --payload ./payloads/sqli_payloads.txt \
       --fields ./payloads/fields.txt \
       --method POST \
       --body-injection \

# Targeting a specific field and using CSRF token
sqlcap --url "https://api.example.com/products" \
       --payload ./payloads/sqli_payloads.txt \
       --fields ./payloads/fields.txt \
       --method POST \
       --body-injection \
       --csrf-token "your-csrf-token" \
       --csrf-field "csrf_token" \
       --csrf-cookie-field "CSRF_COOKIE" \
```

### Understanding the logs

When using the `--debug` flag, the scanner will log all HTTP requests to the specified debug file. Here's an example of what those logs look like:

```
POST /api/users HTTP/1.1
Host: api.example.com
Content-Type: application/json
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: pt-BR,pt;q=0.7
Connection: keep-alive

{
  "id": "1' OR '1'='1",
  "name": "user",
  "csrf_token": "06a1bb9d5e9de4eb22a633d365ff1083"
}
__________
```

### Benefits of Body Injection

- Test APIs that primarily accept JSON payloads
- Detect SQL Injection vulnerabilities in request body parameters
- More realistic testing of modern web applications
- Complete debug logs to understand how requests are formed

### Available Payload Types

The scanner can inject various types of SQL payloads, including:

- Boolean-based blind SQL injection
- Time-based blind SQL injection
- Error-based SQL injection
- UNION-based SQL injection

These payloads will be injected into the specified field in the request body, allowing for comprehensive testing of endpoints that parse and process JSON data. 