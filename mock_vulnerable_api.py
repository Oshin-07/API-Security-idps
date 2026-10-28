"""
Intentionally Vulnerable Mock API Target
For testing the AI-Driven Adaptive API Security Scanner.
Covers OWASP Top 10 API Security Risks:
- SQL Injection (API8:2023 Security Misconfiguration / Injection)
- Reflected Cross-Site Scripting (XSS)
- Broken Authentication (API2:2023)
- Broken Object Level Authorization / IDOR (API1:2023)
- Missing Security Headers (API8:2023)
- Unrestricted Resource Consumption / No Rate Limiting (API4:2023)
"""

import json
import os
from flask import Flask, request, jsonify, make_response

app = Flask(__name__)

# Sample in-memory database
USERS_DB = [
    {"id": "101", "username": "alice", "email": "alice@corp.local", "role": "user", "ssn_last4": "4821"},
    {"id": "102", "username": "bob", "email": "bob@corp.local", "role": "user", "ssn_last4": "9934"},
    {"id": "admin", "username": "administrator", "email": "admin@corp.local", "role": "admin", "ssn_last4": "0001"}
]

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "name": "Intentionally Vulnerable Test API Target",
        "purpose": "Safe local sandbox for API security scanning and risk assessment",
        "docs_url": "/openapi.json",
        "status": "online"
    })

@app.route("/openapi.json", methods=["GET"])
def get_openapi_spec():
    """Serves OpenAPI 3.0 specification for API Discovery Module (Member 1)."""
    spec_path = os.path.join(os.path.dirname(__file__), "sample_openapi.json")
    if os.path.exists(spec_path):
        with open(spec_path, "r", encoding="utf-8-sig") as f:
            return jsonify(json.load(f))
    return jsonify({"error": "Spec file not found"}), 404

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy", "service": "api-gateway"})

@app.route("/api/users/search", methods=["GET"])
def search_users():
    """
    VULNERABILITY: SQL Injection
    Simulates direct string concatenation in a SQL query.
    If SQL syntax payload or quote is present, returns a database error or dumps all users.
    """
    query = request.args.get("query", "")
    
    # Check for SQL injection payloads/signatures
    sqli_signatures = ["'", '"', "OR", "UNION", "--", "/*", "1=1"]
    has_sqli = any(sig.lower() in query.lower() for sig in sqli_signatures)
    
    if "'" in query or '"' in query:
        # Simulate SQLite / MySQL syntax error
        return jsonify({
            "error": "OperationalError: near '" + query + "': syntax error in SQL query: SELECT * FROM users WHERE username = '" + query + "'",
            "db_engine": "SQLite 3.39.0",
            "results": []
        }), 500
    
    if "1=1" in query.replace(" ", "") or "or" in query.lower():
        # Attacker bypassed filter and dumps all users
        return jsonify({
            "status": "success",
            "query_executed": f"SELECT * FROM users WHERE username = '{query}'",
            "matched_records": USERS_DB
        }), 200

    # Normal filtered response
    results = [u for u in USERS_DB if query.lower() in u["username"].lower()]
    return jsonify({"status": "success", "results": results}), 200

@app.route("/api/comments", methods=["POST"])
def post_comment():
    """
    VULNERABILITY: Reflected XSS
    Reflects the input payload without HTML escaping or sanitization.
    """
    data = request.get_json(silent=True) or {}
    username = data.get("username", "anonymous")
    comment = data.get("comment", "")
    
    # Returns raw unescaped input in rendered HTML block
    response_payload = {
        "status": "comment_posted",
        "author": username,
        "raw_comment": comment,
        "rendered_html": f"<div class='user-comment'><b>{username}:</b> {comment}</div>"
    }
    resp = make_response(jsonify(response_payload), 201)
    # Permissive CORS header
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp

@app.route("/api/admin/dashboard", methods=["GET"])
def admin_dashboard():
    """
    VULNERABILITY: Broken Authentication
    Claims to require Bearer auth in spec, but fails to validate or enforce tokens properly!
    """
    auth_header = request.headers.get("Authorization", "")
    
    # Even if missing, malformed, or fake, it allows access or leaks admin secrets
    return jsonify({
        "status": "authenticated",
        "message": "Welcome to the Administrative Dashboard",
        "received_token": auth_header if auth_header else "MISSING_HEADER",
        "system_config": {
            "internal_ip": "10.0.4.12",
            "database_host": "db-prod.internal.local",
            "jwt_secret_hint": "secret_key_hardcoded_123"
        }
    }), 200

@app.route("/api/profile/<user_id>", methods=["GET"])
def get_user_profile(user_id):
    """
    VULNERABILITY: Broken Object Level Authorization (IDOR)
    Allows querying any arbitrary user's private data without checking caller identity.
    """
    user = next((u for u in USERS_DB if str(u["id"]) == str(user_id)), None)
    if user:
        return jsonify({
            "status": "success",
            "profile": user
        }), 200
    return jsonify({"error": f"User ID {user_id} not found"}), 404

@app.route("/api/login", methods=["POST"])
def login():
    """
    VULNERABILITY: No Rate Limiting (Missing Rate Limiting)
    Allows unlimited failed authentication attempts.
    """
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    
    if username == "admin" and password == "SuperSecret2026!":
        return jsonify({"status": "success", "token": "valid_admin_token_jwt_xyz"}), 200
    
    # Fails without any 429 Too Many Requests response
    return jsonify({"status": "failed", "error": "Invalid credentials"}), 401

if __name__ == "__main__":
    print("[*] Starting Vulnerable Test API on http://127.0.0.1:8888 ...")
    app.run(host="127.0.0.1", port=8888, debug=False)
