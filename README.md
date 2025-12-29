# HTTP Digest Authentication Demo

This Python Flask app replicates the HTTP Digest Authentication used in the RATGDO firmware (`web.cpp`).

## How RATGDO Authentication Works

### Server-Side Flow (ESP32/ESP8266)

1. **Protected routes use the `AUTHENTICATE()` macro:**
   ```cpp
   void handle_auth() {
       AUTHENTICATE();
       server.send_P(200, type_txt, PSTR("Authenticated"));
   }
   ```

2. **The macro checks if auth is required and validates credentials:**
   ```cpp
   #define AUTHENTICATE()
       if (userConfig->getPasswordRequired() && 
           !server.authenticate(ratgdoAuthenticate))
           return server.requestAuthentication(DIGEST_AUTH, www_realm);
   ```

3. **Credentials are stored as pre-computed HA1 hash:**
   - When setting password, the client computes: `MD5(username:realm:password)`
   - This hash is stored in NVRAM (never the plain password)
   - Realm is fixed: `"RATGDO Login Required"`

### HTTP Digest Auth Protocol (RFC 2617)

```
Client                                 Server
  |                                      |
  |  GET /auth                           |
  |------------------------------------->|
  |                                      |
  |  401 Unauthorized                    |
  |  WWW-Authenticate: Digest            |
  |    realm="RATGDO Login Required",    |
  |    nonce="abc123...",                |
  |    qop="auth"                        |
  |<-------------------------------------|
  |                                      |
  |  GET /auth                           |
  |  Authorization: Digest               |
  |    username="admin",                 |
  |    realm="...", nonce="...",         |
  |    response="<computed_hash>"        |
  |------------------------------------->|
  |                                      |
  |  200 OK - Authenticated              |
  |<-------------------------------------|
```

### The Hash Computation

```
HA1 = MD5(username:realm:password)        # Pre-stored in NVRAM
HA2 = MD5(method:uri)                     # Computed per-request
response = MD5(HA1:nonce:nc:cnonce:qop:HA2)  # Verified by server
```

**Key Security Feature:** The password is NEVER sent over the wire!

## Running the Demo

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the server
python app.py
```

Then open http://localhost:8080 in your browser.

## Test Credentials

- **Username:** `admin`
- **Password:** `password`

## Testing with curl

```bash
# This will fail with 401:
curl -v http://localhost:8080/auth

# This will succeed with digest auth:
curl -v --digest -u admin:password http://localhost:8080/auth

# Public endpoint (no auth needed):
curl http://localhost:8080/status.json
```

## Files

- `app.py` - Main Flask application with digest auth implementation
- `requirements.txt` - Python dependencies
- `README.md` - This file

## Comparison to RATGDO Code

| RATGDO (C++)                              | Python Demo                         |
|-------------------------------------------|-------------------------------------|
| `server.requestAuthentication()`          | `request_authentication()`          |
| `AUTHENTICATE()` macro                    | `@authenticate` decorator           |
| `userConfig->getwwwCredentials()`         | `WWW_CREDENTIALS` constant          |
| `userConfig->getPasswordRequired()`       | `PASSWORD_REQUIRED` constant        |
| `www_realm` global                        | `WWW_REALM` constant                |

