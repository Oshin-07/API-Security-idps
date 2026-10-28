"""
Member 3: Intelligent Explanation and Remediation Engine
Generates human-readable, educational vulnerability explanations,
threat impact analyses, and actionable code fixes.
"""

from typing import Dict, Any

VULN_KNOWLEDGE_BASE = {
    "SQL Injection": {
        "cwe": "CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)",
        "owasp": "OWASP API8:2023 Security Misconfiguration / Injection",
        "description": "The API endpoint directly incorporates untrusted user input into a dynamic SQL query without parameterization or escaping.",
        "impact": "An attacker can bypass authentication, extract confidential database records (PII, passwords), modify or delete tables, and potentially execute system commands.",
        "remediation": "Use parameterized queries or Object Relational Mapping (ORM) with prepared statements. Never concatenate user input into SQL strings.",
        "code_example": (
            "# INSECURE:\n"
            "query = f\"SELECT * FROM users WHERE name = '{user_input}'\"\n\n"
            "# SECURE (Parameterized Query):\n"
            "cursor.execute(\"SELECT * FROM users WHERE name = %s\", (user_input,))"
        )
    },
    "Reflected Cross-Site Scripting (XSS)": {
        "cwe": "CWE-79 (Improper Neutralization of Input During Web Page Generation)",
        "owasp": "OWASP API8:2023 Security Misconfiguration",
        "description": "User-supplied data is echoed back in the API response without contextual output encoding or sanitization.",
        "impact": "If consumed by a browser frontend, malicious JavaScript can execute in the victim's session, stealing cookies, session tokens, or performing unauthorized actions on their behalf.",
        "remediation": "Apply contextual output encoding (HTML, JavaScript, URL encoding). Enforce strict Content-Security-Policy (CSP) headers.",
        "code_example": (
            "# INSECURE:\n"
            "return f\"<div>Comment: {comment}</div>\"\n\n"
            "# SECURE (HTML Escaping):\n"
            "import html\n"
            "safe_comment = html.escape(comment)\n"
            "return f\"<div>Comment: {safe_comment}</div>\""
        )
    },
    "Broken Authentication": {
        "cwe": "CWE-287 (Improper Authentication)",
        "owasp": "OWASP API2:2023 Broken Authentication",
        "description": "The API fails to strictly enforce, validate, or verify authentication tokens on protected endpoints.",
        "impact": "Unauthenticated attackers can access sensitive administrative interfaces, leak configuration details, and compromise the entire backend infrastructure.",
        "remediation": "Enforce mandatory authentication verification via middleware/dependency injection. Validate cryptographic signatures and expiration of JWT tokens on every request.",
        "code_example": (
            "# SECURE (FastAPI Dependency Enforcement):\n"
            "from fastapi import Depends, HTTPException, status\n"
            "from fastapi.security import HTTPBearer\n\n"
            "security = HTTPBearer()\n\n"
            "def verify_token(credentials = Depends(security)):\n"
            "    token = credentials.credentials\n"
            "    if not validate_jwt(token):\n"
            "        raise HTTPException(status_code=401, detail='Invalid or missing token')\n"
            "    return get_current_user(token)"
        )
    },
    "Broken Object Level Authorization (IDOR)": {
        "cwe": "CWE-639 (Authorization Bypass Through User-Controlled Key)",
        "owasp": "OWASP API1:2023 Broken Object Level Authorization (BOLA/IDOR)",
        "description": "The endpoint accepts an object ID directly from the client and retrieves data without verifying if the requesting user owns that resource.",
        "impact": "Attackers can systematically enumerate IDs and harvest private personal, financial, or confidential data belonging to any other user in the system.",
        "remediation": "Implement record-level authorization checks. Always compare the session user ID with the owner ID of the requested resource before returning records.",
        "code_example": (
            "# INSECURE:\n"
            "user = db.query(User).filter_by(id=user_id).first()\n\n"
            "# SECURE (Ownership Verification):\n"
            "if current_user.id != requested_id and not current_user.is_admin:\n"
            "    raise HTTPException(status_code=403, detail='Access forbidden: not your resource')"
        )
    },
    "Missing Security Header": {
        "cwe": "CWE-1021 / CWE-319 (Security Misconfiguration)",
        "owasp": "OWASP API8:2023 Security Misconfiguration",
        "description": "The API server omits industry-standard defensive HTTP response headers (such as HSTS, CSP, X-Frame-Options, and X-Content-Type-Options).",
        "impact": "Leaves client browsers vulnerable to protocol downgrade attacks, Clickjacking, MIME-type sniffing, and cross-site scripting exploitation.",
        "remediation": "Configure web server (Nginx/Apache) or application middleware to return defensive security headers on all responses.",
        "code_example": (
            "# Recommended Headers:\n"
            "Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
            "Content-Security-Policy: default-src 'self'\n"
            "X-Frame-Options: DENY\n"
            "X-Content-Type-Options: nosniff"
        )
    },
    "Missing Rate Limiting": {
        "cwe": "CWE-799 (Improper Control of Generation of Code or Resource Consumption)",
        "owasp": "OWASP API4:2023 Unrestricted Resource Consumption",
        "description": "The API does not restrict the number of incoming requests within a given timeframe, allowing unrestricted request bursts.",
        "impact": "Enables brute-force credential stuffing, API denial of service (DoS), resource exhaustion, and automated credential scraping.",
        "remediation": "Implement token-bucket or sliding-window rate limiting (e.g., using Redis or SlowAPI in FastAPI) returning HTTP 429 Too Many Requests.",
        "code_example": (
            "# SECURE (Using SlowAPI Rate Limiter in FastAPI):\n"
            "from slowapi import Limiter\n"
            "from slowapi.util import get_remote_address\n\n"
            "limiter = Limiter(key_func=get_remote_address)\n"
            "@app.post('/api/login')\n"
            "@limiter.limit('5/minute')\n"
            "def login():\n"
            "    ..."
        )
    }
}

class ExplanationEngine:
    def explain_vulnerability(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Returns structured explanation, threat impact, and code remediation."""
        v_type = finding.get("vulnerability_type", "")
        
        # Match knowledge base
        kb_entry = None
        for key, val in VULN_KNOWLEDGE_BASE.items():
            if key.lower() in v_type.lower():
                kb_entry = val
                break

        if not kb_entry:
            kb_entry = {
                "cwe": finding.get("cwe_id", "CWE-Unknown"),
                "owasp": "OWASP API Security Top 10",
                "description": f"Detected security anomaly: {v_type}",
                "impact": "Potential compromise of confidentiality, integrity, or availability.",
                "remediation": "Review endpoint logic and enforce strict input validation and access controls.",
                "code_example": "# Enforce strict validation and authentication."
            }

        return {
            "finding_id": finding.get("id"),
            "vulnerability_type": v_type,
            "severity": finding.get("severity"),
            "endpoint": f"{finding.get('method')} {finding.get('endpoint')}",
            "cwe_reference": kb_entry["cwe"],
            "owasp_category": kb_entry["owasp"],
            "technical_description": kb_entry["description"],
            "attack_impact": kb_entry["impact"],
            "remediation_guidance": kb_entry["remediation"],
            "secure_code_example": kb_entry["code_example"]
        }

    def generate_executive_summary(self, risk_data: Dict[str, Any]) -> str:
        """Generates a high-level summary suitable for presentation and management."""
        score = risk_data.get("overall_risk_score", 0)
        level = risk_data.get("threat_level", "LOW")
        total_vulns = risk_data.get("total_findings", 0)
        breakdown = risk_data.get("severity_breakdown", {})

        summary = (
            f"EXECUTIVE SECURITY ASSESSMENT SUMMARY:\n"
            f"- Overall System Risk Score: {score}/100 ({level})\n"
            f"- Estimated CVSS Base Score: {risk_data.get('cvss_base_score', 0.0)}/10.0\n"
            f"- Total Detected Vulnerabilities: {total_vulns}\n"
            f"  * Critical: {breakdown.get('Critical', 0)}\n"
            f"  * High:     {breakdown.get('High', 0)}\n"
            f"  * Medium:   {breakdown.get('Medium', 0)}\n"
            f"  * Low:      {breakdown.get('Low', 0)}\n\n"
            f"Key Takeaway: The target API exhibits {breakdown.get('Critical', 0)} critical vulnerabilities "
            f"that require immediate mitigation before production release."
        )
        return summary
