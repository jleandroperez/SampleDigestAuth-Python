"""
Sample Python Flask app demonstrating HTTP Digest Authentication.
This replicates the authentication mechanism used in the RATGDO firmware.

HTTP Digest Authentication (RFC 2617/7616) works as follows:
1. Client requests a protected resource
2. Server responds with 401 Unauthorized + WWW-Authenticate header containing:
   - realm: A string describing the protected area
   - nonce: A server-generated unique value (prevents replay attacks)
   - qop: Quality of protection (auth or auth-int)
3. Client computes a response hash and retries with Authorization header containing:
   - username, realm, nonce, uri, response (the hash), etc.
4. Server validates the response hash

The key security feature: the password is never sent over the wire.
Instead, both client and server compute:
   HA1 = MD5(username:realm:password)
   HA2 = MD5(method:uri)
   response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
"""

from flask import Flask, request, Response, jsonify
import hashlib
import secrets
import time
from functools import wraps

app = Flask(__name__)

# Configuration - matches RATGDO's approach
WWW_REALM = "RATGDO Login Required"
WWW_USERNAME = "admin"
PASSWORD_REQUIRED = True

# Store the pre-computed HA1 hash (username:realm:password)
# In RATGDO, this is stored in NVRAM via userConfig->getwwwCredentials()
# Default password is "password" for this demo
def compute_ha1(username: str, realm: str, password: str) -> str:
    """Compute HA1 = MD5(username:realm:password)"""
    return hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()

# Pre-computed credential (HA1) - this is what gets stored
WWW_CREDENTIALS = compute_ha1(WWW_USERNAME, WWW_REALM, "password")

# Store active nonces with their creation time (for expiration)
# In production, use Redis or similar for distributed systems
active_nonces: dict[str, float] = {}
NONCE_EXPIRY_SECONDS = 300  # 5 minutes


def generate_nonce() -> str:
    """Generate a unique nonce for digest authentication."""
    nonce = secrets.token_hex(16)
    active_nonces[nonce] = time.time()
    # Clean up expired nonces
    current_time = time.time()
    expired = [n for n, t in active_nonces.items() 
               if current_time - t > NONCE_EXPIRY_SECONDS]
    for n in expired:
        del active_nonces[n]
    return nonce


def parse_digest_auth(auth_header: str) -> dict:
    """Parse the Authorization: Digest header into a dictionary."""
    if not auth_header.startswith("Digest "):
        return {}
    
    auth_str = auth_header[7:]  # Remove "Digest " prefix
    params = {}
    
    # Parse key="value" pairs (handles both quoted and unquoted values)
    import re
    pattern = r'(\w+)=(?:"([^"]+)"|([^,\s]+))'
    for match in re.finditer(pattern, auth_str):
        key = match.group(1)
        value = match.group(2) if match.group(2) else match.group(3)
        params[key] = value
    
    return params


def verify_digest_auth(auth_params: dict, method: str, stored_ha1: str) -> bool:
    """
    Verify the digest authentication response.
    
    The client computes:
        HA1 = MD5(username:realm:password)
        HA2 = MD5(method:uri)
        response = MD5(HA1:nonce:nc:cnonce:qop:HA2)  [when qop is present]
        response = MD5(HA1:nonce:HA2)                 [when qop is absent]
    
    We verify by computing the same and comparing.
    """
    required_fields = ['username', 'realm', 'nonce', 'uri', 'response']
    if not all(field in auth_params for field in required_fields):
        return False
    
    # Verify nonce is valid and not expired
    nonce = auth_params['nonce']
    if nonce not in active_nonces:
        return False
    if time.time() - active_nonces[nonce] > NONCE_EXPIRY_SECONDS:
        del active_nonces[nonce]
        return False
    
    # Verify realm matches
    if auth_params['realm'] != WWW_REALM:
        return False
    
    # HA1 is already computed and stored (username:realm:password)
    ha1 = stored_ha1
    
    # Compute HA2 = MD5(method:uri)
    ha2 = hashlib.md5(f"{method}:{auth_params['uri']}".encode()).hexdigest()
    
    # Compute expected response
    if 'qop' in auth_params:
        # RFC 2617 with qop (quality of protection)
        # response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
        nc = auth_params.get('nc', '')
        cnonce = auth_params.get('cnonce', '')
        qop = auth_params['qop']
        expected = hashlib.md5(
            f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()
        ).hexdigest()
    else:
        # RFC 2069 compatibility (no qop)
        # response = MD5(HA1:nonce:HA2)
        expected = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
    
    return auth_params['response'] == expected


def request_authentication():
    """
    Return a 401 response with WWW-Authenticate header.
    This is equivalent to server.requestAuthentication(DIGEST_AUTH, www_realm) in RATGDO.
    """
    nonce = generate_nonce()
    
    # Build the WWW-Authenticate header
    auth_header = (
        f'Digest realm="{WWW_REALM}", '
        f'nonce="{nonce}", '
        f'qop="auth", '
        f'algorithm=MD5'
    )
    
    response = Response("401 Unauthorized\n", status=401, mimetype='text/plain')
    response.headers['WWW-Authenticate'] = auth_header
    return response


def authenticate(f):
    """
    Decorator that implements the AUTHENTICATE() macro from RATGDO.
    
    In C++:
        #define AUTHENTICATE()
            if (userConfig->getPasswordRequired() && 
                !server.authenticate(ratgdoAuthenticate))
                return server.requestAuthentication(DIGEST_AUTH, www_realm);
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        # Skip auth if password not required (like RATGDO's getPasswordRequired())
        if not PASSWORD_REQUIRED:
            return f(*args, **kwargs)
        
        # Check for Authorization header
        auth_header = request.headers.get('Authorization', '')
        
        if not auth_header:
            # No auth header, request authentication
            return request_authentication()
        
        # Parse and verify digest auth
        auth_params = parse_digest_auth(auth_header)
        
        if not verify_digest_auth(auth_params, request.method, WWW_CREDENTIALS):
            # Invalid credentials, request authentication again
            return request_authentication()
        
        # Authentication successful
        return f(*args, **kwargs)
    
    return decorated


# ============================================================================
# Routes - Replicating RATGDO's endpoint structure
# ============================================================================

@app.route('/auth', methods=['GET'])
@authenticate
def handle_auth():
    """
    Equivalent to RATGDO's handle_auth():
        void handle_auth() {
            AUTHENTICATE();
            server.send_P(200, type_txt, PSTR("Authenticated"));
        }
    """
    return Response("Authenticated", status=200, mimetype='text/plain')


@app.route('/logout', methods=['GET'])
def handle_logout():
    """
    Equivalent to RATGDO's handle_logout():
        void handle_logout() {
            return server.requestAuthentication(DIGEST_AUTH, www_realm);
        }
    Forces browser to forget credentials by returning 401.
    """
    return request_authentication()


@app.route('/status.json', methods=['GET'])
def handle_status():
    """
    Public endpoint - no authentication required.
    Returns device status as JSON.
    """
    return jsonify({
        "deviceName": "RATGDO-Demo",
        "userName": WWW_USERNAME,
        "passwordRequired": PASSWORD_REQUIRED,
        "firmwareVersion": "1.0.0-python-demo",
        "upTime": int(time.time()),
    })


@app.route('/setgdo', methods=['POST'])
@authenticate
def handle_setgdo():
    """
    Protected endpoint - requires authentication.
    Handles setting device parameters.
    """
    # Get form data
    data = request.form.to_dict()
    print(f"Received settings: {data}")
    return Response("Settings updated\n", status=200, mimetype='text/plain')


@app.route('/reset', methods=['POST'])
@authenticate
def handle_reset():
    """
    Protected endpoint - requires authentication.
    Would reset/unpair the device.
    """
    return Response("Device reset (simulated)\n", status=200, mimetype='text/plain')


@app.route('/')
def index():
    """Serve a simple test page."""
    return '''
<!DOCTYPE html>
<html>
<head>
    <title>Digest Auth Demo</title>
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            max-width: 600px; 
            margin: 50px auto; 
            padding: 20px;
            background: #1a1a2e;
            color: #eee;
        }
        h1 { color: #00d9ff; }
        button {
            background: #00d9ff;
            color: #1a1a2e;
            border: none;
            padding: 10px 20px;
            margin: 5px;
            cursor: pointer;
            border-radius: 4px;
            font-weight: bold;
        }
        button:hover { background: #00b8d4; }
        #result {
            margin-top: 20px;
            padding: 15px;
            background: #16213e;
            border-radius: 4px;
            white-space: pre-wrap;
            font-family: monospace;
        }
        .info {
            background: #16213e;
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <h1>🔐 HTTP Digest Auth Demo</h1>
    
    <div class="info">
        <strong>Credentials:</strong><br>
        Username: <code>admin</code><br>
        Password: <code>password</code>
    </div>
    
    <button onclick="checkAuth()">Check Auth (/auth)</button>
    <button onclick="getStatus()">Get Status (/status.json)</button>
    <button onclick="logout()">Logout</button>
    
    <div id="result">Click a button to test...</div>
    
    <script>
        async function checkAuth() {
            try {
                const resp = await fetch('/auth');
                const text = await resp.text();
                document.getElementById('result').textContent = 
                    `Status: ${resp.status}\\nResponse: ${text}`;
            } catch (e) {
                document.getElementById('result').textContent = 'Error: ' + e;
            }
        }
        
        async function getStatus() {
            try {
                const resp = await fetch('/status.json');
                const json = await resp.json();
                document.getElementById('result').textContent = 
                    `Status: ${resp.status}\\nResponse:\\n${JSON.stringify(json, null, 2)}`;
            } catch (e) {
                document.getElementById('result').textContent = 'Error: ' + e;
            }
        }
        
        async function logout() {
            try {
                const resp = await fetch('/logout');
                document.getElementById('result').textContent = 
                    `Status: ${resp.status} (credentials cleared)\\nNext /auth request will require login.`;
            } catch (e) {
                document.getElementById('result').textContent = 'Error: ' + e;
            }
        }
    </script>
</body>
</html>
'''


if __name__ == '__main__':
    print(f"\n{'='*60}")
    print("HTTP Digest Authentication Demo Server")
    print(f"{'='*60}")
    print(f"Realm:    {WWW_REALM}")
    print(f"Username: {WWW_USERNAME}")
    print(f"Password: password")
    print(f"HA1 hash: {WWW_CREDENTIALS}")
    print(f"{'='*60}\n")
    
    app.run(host='0.0.0.0', port=8080, debug=True)

