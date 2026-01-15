# Flask Security Hardening Guide

This guide provides code snippets and configuration recommendations to secure Flask applications against common vulnerabilities, especially mass assignment and information disclosure via stack traces.

## Table of Contents

1. [Disable Debug Mode in Production](#disable-debug-mode-in-production)
2. [Input Validation & Mass Assignment Protection](#input-validation--mass-assignment-protection)
3. [Error Handling & Stack Trace Sanitization](#error-handling--stack-trace-sanitization)
4. [Security Headers](#security-headers)
5. [Deployment Checklist](#deployment-checklist)

---

## 1. Disable Debug Mode in Production

**Problem:** Debug mode exposes stack traces, interactive debugger, and internal application details to clients.

**Solution:** Always disable debug mode in production/staging/test environments.

### app.py

```python
import os
from flask import Flask

app = Flask(__name__)

# CRITICAL: Never run with debug=True in non-development environments
# Use environment variable to control debug mode
app.config['DEBUG'] = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'

# Alternative: explicitly disable in production
if os.environ.get('FLASK_ENV') == 'production':
    app.config['DEBUG'] = False
    app.config['TESTING'] = False

if __name__ == '__main__':
    # Do NOT use debug=True here for network-accessible instances
    app.run(host='0.0.0.0', port=5001, debug=app.config['DEBUG'])
```

### Environment Variables

```bash
# .env (development)
FLASK_ENV=development
FLASK_DEBUG=True

# .env.production
FLASK_ENV=production
FLASK_DEBUG=False
```

---

## 2. Input Validation & Mass Assignment Protection

**Problem:** APIs accept and persist user-supplied fields without validation, allowing attackers to set sensitive attributes (e.g., `is_admin`, `limit`, `ownerId`).

**Solution:** Use an allowlist of permitted fields and validate all input.

### Manual Validation (Simple)

```python
from flask import Flask, request, jsonify
from werkzeug.exceptions import BadRequest

app = Flask(__name__)

# Define allowed fields for each endpoint
ALLOWED_VIRTUAL_CARD_FIELDS = {'cardholderName', 'currency', 'cvv', 'expiryDate'}

@app.route('/api/virtual-cards/create', methods=['POST'])
def create_virtual_card():
    try:
        data = request.get_json(force=True)
    except Exception:
        raise BadRequest('Invalid JSON')

    # Detect forbidden fields
    forbidden = set(data.keys()) - ALLOWED_VIRTUAL_CARD_FIELDS
    if forbidden:
        return jsonify({
            'error': 'Invalid fields in payload',
            'invalid_fields': list(forbidden)
        }), 400

    # Extract only allowed fields
    card_data = {k: data[k] for k in ALLOWED_VIRTUAL_CARD_FIELDS if k in data}

    # Set server-controlled fields (NOT from user input)
    card_data['limit'] = 1000  # default limit
    card_data['ownerId'] = get_current_user_id()  # from session
    card_data['isBlocked'] = False
    card_data['isAdmin'] = False  # NEVER allow user to set this

    # ... create card in database ...
    
    return jsonify({'success': True, 'card': card_data}), 201
```

### Using Marshmallow (Recommended)

```python
from flask import Flask, request, jsonify
from marshmallow import Schema, fields, ValidationError, EXCLUDE

app = Flask(__name__)

class VirtualCardCreateSchema(Schema):
    class Meta:
        unknown = EXCLUDE  # Ignore unknown fields (or use RAISE to reject them)
    
    cardholderName = fields.Str(required=True, validate=lambda x: len(x) > 0)
    currency = fields.Str(required=True, validate=lambda x: x in ['USD', 'EUR', 'GBP'])
    cvv = fields.Str(required=False)
    expiryDate = fields.Date(required=False)
    # Note: limit, ownerId, isAdmin are NOT included here

@app.route('/api/virtual-cards/create', methods=['POST'])
def create_virtual_card():
    schema = VirtualCardCreateSchema()
    
    try:
        # Validate and deserialize input (will reject unknown fields if Meta.unknown = RAISE)
        card_data = schema.load(request.get_json())
    except ValidationError as err:
        return jsonify({'error': 'Validation failed', 'details': err.messages}), 422
    
    # Set server-controlled fields
    card_data['limit'] = 1000
    card_data['ownerId'] = get_current_user_id()
    card_data['isBlocked'] = False
    
    # ... create card in database ...
    
    return jsonify({'success': True, 'card': card_data}), 201
```

---

## 3. Error Handling & Stack Trace Sanitization

**Problem:** Unhandled exceptions expose stack traces, file paths, and internal logic to clients.

**Solution:** Install global error handlers that log exceptions server-side but return sanitized responses to clients.

### Global Error Handlers

```python
from flask import Flask, jsonify
from werkzeug.exceptions import HTTPException, BadRequest, Unauthorized, Forbidden, NotFound
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Handle specific HTTP exceptions
@app.errorhandler(BadRequest)
def handle_bad_request(e):
    return jsonify({'error': 'Bad request', 'message': str(e.description)}), 400

@app.errorhandler(Unauthorized)
def handle_unauthorized(e):
    return jsonify({'error': 'Unauthorized', 'message': 'Authentication required'}), 401

@app.errorhandler(Forbidden)
def handle_forbidden(e):
    return jsonify({'error': 'Forbidden', 'message': 'Insufficient permissions'}), 403

@app.errorhandler(NotFound)
def handle_not_found(e):
    return jsonify({'error': 'Not found', 'message': 'Resource not found'}), 404

# Handle all other HTTP exceptions
@app.errorhandler(HTTPException)
def handle_http_exception(e):
    logger.warning(f'HTTP {e.code}: {e.description}')
    return jsonify({'error': e.name, 'message': e.description}), e.code

# Handle uncaught exceptions (CRITICAL for production)
@app.errorhandler(Exception)
def handle_uncaught_exception(e):
    # Log full exception with stack trace server-side
    logger.exception('Unhandled exception:')
    
    # Return sanitized response to client (no stack trace)
    return jsonify({
        'error': 'Internal server error',
        'message': 'An unexpected error occurred. Please try again later.'
    }), 500
```

### Suppress Werkzeug Debugger

Ensure the interactive debugger is disabled:

```python
app.config['PROPAGATE_EXCEPTIONS'] = False  # Don't re-raise exceptions in production
```

---

## 4. Security Headers

Add security headers to all responses:

```python
from flask import Flask

app = Flask(__name__)

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    # Remove server header to avoid version disclosure
    response.headers.pop('Server', None)
    return response
```

Or use Flask-Talisman:

```bash
pip install flask-talisman
```

```python
from flask import Flask
from flask_talisman import Talisman

app = Flask(__name__)
Talisman(app, force_https=False)  # Set force_https=True in production
```

---

## 5. Deployment Checklist

Before deploying to production/staging/CI:

- [ ] `FLASK_DEBUG=False` in environment variables
- [ ] `FLASK_ENV=production` set
- [ ] Global error handlers installed (no stack traces exposed)
- [ ] Input validation implemented for all POST/PUT/PATCH endpoints
- [ ] Mass assignment protection: use allowlists for permitted fields
- [ ] Security headers added to all responses
- [ ] Logging configured to capture errors server-side
- [ ] Secrets (database credentials, API keys) stored in environment variables, not hardcoded
- [ ] HTTPS enabled (via reverse proxy or `force_https=True` in Talisman)

---

## Testing Your Security Improvements

### 1. Verify Stack Traces Are Hidden

```bash
# Send invalid input
curl -X POST http://localhost:5001/api/virtual-cards/create \
  -H "Content-Type: application/json" \
  -d '{"invalid": "data"}'

# Expected: {"error": "...", "message": "..."}
# NOT expected: HTML with traceback or file paths
```

### 2. Verify Mass Assignment Is Blocked

```bash
# Attempt to set sensitive fields
curl -X POST http://localhost:5001/api/virtual-cards/create \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"cardholderName":"Test","currency":"USD","limit":9999999,"isAdmin":true}'

# Expected: 400/422 with error message about invalid fields
# NOT expected: 200/201 with isAdmin=true in response
```

### 3. Run Automated Security Tests

```bash
# From your test repository
npx playwright test tests/security/
```

---

## Additional Resources

- [OWASP Top 10 API Security Risks](https://owasp.org/www-project-api-security/)
- [Flask Security Best Practices](https://flask.palletsprojects.com/en/2.3.x/security/)
- [Marshmallow Documentation](https://marshmallow.readthedocs.io/)
- [Flask-Talisman](https://github.com/GoogleCloudPlatform/flask-talisman)

---

## Example: Complete Secure Endpoint

```python
from flask import Flask, request, jsonify
from marshmallow import Schema, fields, ValidationError, EXCLUDE
from werkzeug.exceptions import Unauthorized
import logging

app = Flask(__name__)
logger = logging.getLogger(__name__)

class VirtualCardCreateSchema(Schema):
    class Meta:
        unknown = EXCLUDE
    
    cardholderName = fields.Str(required=True)
    currency = fields.Str(required=True, validate=lambda x: x in ['USD', 'EUR', 'GBP'])

@app.route('/api/virtual-cards/create', methods=['POST'])
def create_virtual_card():
    # 1. Validate input
    schema = VirtualCardCreateSchema()
    try:
        card_data = schema.load(request.get_json())
    except ValidationError as err:
        return jsonify({'error': 'Validation failed', 'details': err.messages}), 422
    
    # 2. Authenticate user (get from session/JWT)
    user_id = get_current_user_id()
    if not user_id:
        raise Unauthorized('Authentication required')
    
    # 3. Set server-controlled fields (NOT from user input)
    card_data['limit'] = 1000
    card_data['ownerId'] = user_id
    card_data['isBlocked'] = False
    
    # 4. Create card in database
    # card = db.create_virtual_card(card_data)
    
    # 5. Return sanitized response
    return jsonify({'success': True, 'card': card_data}), 201

@app.errorhandler(Exception)
def handle_exception(e):
    logger.exception('Unhandled exception')
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run(debug=False)
```

---

**Questions or improvements?** Open an issue or submit a PR!
