"""
Member 2: Vulnerability Scanner Module
--------------------------------------
Responsibilities:
1. SQL Injection testing.
2. Cross-Site Scripting (XSS) testing.
3. Authentication testing (Broken Auth / Missing Auth).
4. Authorization & IDOR testing.
5. Security Header auditing (HSTS, CSP, X-Frame-Options, CORS).
6. Rate-limit testing (Burst request resilience).
7. Structured vulnerability recording ready for AI Risk Assessment and Dashboard.
"""

import sys
import os
import json
import time
import argparse
from typing import Dict, List, Any
import requests

# Add parent directory to path so relative imports work seamlessly
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from core.scanner.payloads import (
    SQLI_PAYLOADS,
    SQLI_ERROR_SIGNATURES,
    XSS_PAYLOADS,
    COMMON_SECURITY_HEADERS,
    AUTH_BYPASS_TOKENS,
    IDOR_TEST_IDS
)

class APIVulnerabilityScanner:
    def __init__(self, base_url: str = "http://127.0.0.1:8888", timeout: int = 5, progress_callback=None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.vuln_counter = 1
        self.progress_callback = progress_callback

    def _record_vulnerability(
        self,
        vuln_type: str,
        severity: str,
        endpoint: str,
        method: str,
        parameter: str,
        payload_used: str,
        http_status: int,
        evidence: str,
        confidence: float,
        cwe_id: str
    ):
        finding = {
            "id": f"VULN-{self.vuln_counter:03d}",
            "vulnerability_type": vuln_type,
            "severity": severity,
            "endpoint": endpoint,
            "method": method.upper(),
            "parameter": parameter,
            "payload_used": payload_used,
            "http_status": http_status,
            "evidence": evidence,
            "confidence": confidence,
            "cwe_id": cwe_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
        self.vulnerabilities.append(finding)
        self.vuln_counter += 1
        print(f" [!] {severity.upper()} FOUND: {vuln_type} at {method} {endpoint} (Param: {parameter})")

    def _progress(self, message: str, percent: int):
        if self.progress_callback:
            try:
                self.progress_callback(message, percent)
            except Exception:
                pass

    # 1. Security Headers & CORS Check
    def check_security_headers(self):
        print(f"[*] Checking Security Headers on {self.base_url} ...")
        try:
            resp = requests.get(self.base_url, timeout=self.timeout)
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}

            # Check missing headers
            for header in COMMON_SECURITY_HEADERS:
                h_name = header["name"]
                if h_name.lower() not in resp_headers:
                    self._record_vulnerability(
                        vuln_type="Missing Security Header",
                        severity=header["severity"],
                        endpoint="/",
                        method="GET",
                        parameter=h_name,
                        payload_used="Passive Header Inspection",
                        http_status=resp.status_code,
                        evidence=f"Missing recommended security header: {h_name}. {header['description']}",
                        confidence=0.99,
                        cwe_id=header["cwe"]
                    )

            # Check Overly Permissive CORS
            cors_header = resp_headers.get("access-control-allow-origin")
            if cors_header == "*":
                self._record_vulnerability(
                    vuln_type="Permissive CORS Policy",
                    severity="Medium",
                    endpoint="/",
                    method="GET",
                    parameter="Access-Control-Allow-Origin",
                    payload_used="Header Inspection",
                    http_status=resp.status_code,
                    evidence="Access-Control-Allow-Origin is set to wildcard '*', allowing any origin to read responses.",
                    confidence=0.95,
                    cwe_id="CWE-942"
                )
        except Exception as e:
            print(f"[!] Error checking security headers: {e}")

    # 2. SQL Injection Testing
    def test_sql_injection(self, endpoint: Dict[str, Any]):
        path = endpoint["path"]
        method = endpoint["method"]
        params = endpoint.get("parameters", [])
        body_schema = endpoint.get("body_schema", {})

        url = f"{self.base_url}{path}"

        # Test query parameters
        for param in params:
            if param.get("in") == "query":
                p_name = param["name"]
                for payload in SQLI_PAYLOADS:
                    try:
                        r = requests.request(method, url, params={p_name: payload}, timeout=self.timeout)
                        body_lower = r.text.lower()
                        # Check error signatures
                        for sig in SQLI_ERROR_SIGNATURES:
                            if sig in body_lower:
                                self._record_vulnerability(
                                    vuln_type="SQL Injection",
                                    severity="Critical",
                                    endpoint=path,
                                    method=method,
                                    parameter=p_name,
                                    payload_used=payload,
                                    http_status=r.status_code,
                                    evidence=f"Database error signature matched: '{sig}' in HTTP {r.status_code} response.",
                                    confidence=0.98,
                                    cwe_id="CWE-89"
                                )
                                return # Avoid duplicate findings on same param
                    except Exception:
                        continue

        # Test JSON body properties
        if method in ["POST", "PUT", "PATCH"] and body_schema.get("properties"):
            props = body_schema["properties"]
            for field in props.keys():
                for payload in SQLI_PAYLOADS:
                    test_body = {k: "test" for k in props.keys()}
                    test_body[field] = payload
                    try:
                        r = requests.request(method, url, json=test_body, timeout=self.timeout)
                        body_lower = r.text.lower()
                        for sig in SQLI_ERROR_SIGNATURES:
                            if sig in body_lower:
                                self._record_vulnerability(
                                    vuln_type="SQL Injection",
                                    severity="Critical",
                                    endpoint=path,
                                    method=method,
                                    parameter=field,
                                    payload_used=payload,
                                    http_status=r.status_code,
                                    evidence=f"SQL error pattern '{sig}' detected in request body injection.",
                                    confidence=0.98,
                                    cwe_id="CWE-89"
                                )
                                return
                    except Exception:
                        continue

    # 3. Cross-Site Scripting (XSS) Testing
    def test_xss(self, endpoint: Dict[str, Any]):
        path = endpoint["path"]
        method = endpoint["method"]
        params = endpoint.get("parameters", [])
        body_schema = endpoint.get("body_schema", {})
        url = f"{self.base_url}{path}"

        # Test query params
        for param in params:
            if param.get("in") == "query":
                p_name = param["name"]
                for payload in XSS_PAYLOADS:
                    try:
                        r = requests.request(method, url, params={p_name: payload}, timeout=self.timeout)
                        # If raw unescaped payload is reflected in response
                        if payload in r.text:
                            self._record_vulnerability(
                                vuln_type="Reflected Cross-Site Scripting (XSS)",
                                severity="High",
                                endpoint=path,
                                method=method,
                                parameter=p_name,
                                payload_used=payload,
                                http_status=r.status_code,
                                evidence=f"Unsanitized payload reflected directly in response text: {payload[:40]}...",
                                confidence=0.92,
                                cwe_id="CWE-79"
                            )
                            return
                    except Exception:
                        continue

        # Test POST/PUT JSON body
        if method in ["POST", "PUT"] and (body_schema.get("properties") or path == "/api/comments"):
            props = body_schema.get("properties", {"username": {}, "comment": {}})
            for field in props.keys():
                for payload in XSS_PAYLOADS:
                    test_body = {k: "test" for k in props.keys()}
                    test_body[field] = payload
                    try:
                        r = requests.request(method, url, json=test_body, timeout=self.timeout)
                        if payload in r.text:
                            self._record_vulnerability(
                                vuln_type="Reflected Cross-Site Scripting (XSS)",
                                severity="High",
                                endpoint=path,
                                method=method,
                                parameter=field,
                                payload_used=payload,
                                http_status=r.status_code,
                                evidence=f"Unescaped HTML/JS payload reflected in rendered response body: {payload}",
                                confidence=0.95,
                                cwe_id="CWE-79"
                            )
                            return
                    except Exception:
                        continue

    # 4. Authentication Testing
    def test_authentication(self, endpoint: Dict[str, Any]):
        path = endpoint["path"]
        method = endpoint["method"]
        auth_required = endpoint.get("auth_required", False)

        # Focus on endpoints that declare auth or look sensitive (/admin, /profile, /settings)
        if not auth_required and not any(k in path.lower() for k in ["admin", "secret", "private"]):
            return

        # Prepare URL (substitute path params with dummy if present)
        test_path = path.replace("{user_id}", "101").replace("{id}", "1")
        url = f"{self.base_url}{test_path}"

        for token in AUTH_BYPASS_TOKENS:
            headers = {}
            if token is not None:
                headers["Authorization"] = token

            try:
                r = requests.request(method, url, headers=headers, timeout=self.timeout)
                # If endpoint is accessed with 200 OK despite missing or fake token
                if r.status_code == 200:
                    token_label = "None (Missing Header)" if token is None else token
                    self._record_vulnerability(
                        vuln_type="Broken Authentication",
                        severity="Critical",
                        endpoint=path,
                        method=method,
                        parameter="Authorization Header",
                        payload_used=f"Token: {token_label}",
                        http_status=r.status_code,
                        evidence=f"Endpoint marked as requiring authentication responded with HTTP 200 OK when supplied with: '{token_label}'",
                        confidence=0.96,
                        cwe_id="CWE-287"
                    )
                    return
            except Exception:
                continue

    # 5. Authorization & IDOR Testing
    def test_idor(self, endpoint: Dict[str, Any]):
        path = endpoint["path"]
        method = endpoint["method"]

        # Check if path has ID placeholders like {user_id}, {id}, {account_id}
        if "{" in path and "}" in path:
            print(f"[*] Testing IDOR / Broken Object Level Authorization on {path} ...")
            param_name = path[path.find("{")+1:path.find("}")]
            
            # Request multiple IDs without authentication or with static user token
            successful_access = []
            for test_id in IDOR_TEST_IDS:
                test_path = path.replace(f"{{{param_name}}}", test_id)
                url = f"{self.base_url}{test_path}"
                try:
                    r = requests.request(method, url, timeout=self.timeout)
                    if r.status_code == 200 and ("email" in r.text.lower() or "role" in r.text.lower() or "ssn" in r.text.lower() or "profile" in r.text.lower()):
                        successful_access.append((test_id, r.status_code))
                except Exception:
                    continue

            if len(successful_access) >= 2:
                # Successfully accessed multiple distinct user records without caller verification
                self._record_vulnerability(
                    vuln_type="Broken Object Level Authorization (IDOR)",
                    severity="High",
                    endpoint=path,
                    method=method,
                    parameter=param_name,
                    payload_used=f"Sequential IDs: {[a[0] for a in successful_access]}",
                    http_status=200,
                    evidence=f"Arbitrary object IDs accessed without ownership verification. Accessible objects: {[a[0] for a in successful_access]}",
                    confidence=0.90,
                    cwe_id="CWE-639"
                )

    # 6. Rate-Limit Testing
    def test_rate_limiting(self, endpoint: Dict[str, Any], burst_count: int = 15):
        path = endpoint["path"]
        method = endpoint["method"]

        # Target auth, login, and token endpoints
        if not any(k in path.lower() for k in ["login", "token", "auth", "register", "password"]):
            return

        print(f"[*] Testing Rate Limiting on {path} with burst of {burst_count} requests ...")
        url = f"{self.base_url}{path}"
        test_payload = {"username": "admin", "password": "wrong_password_test"}

        status_codes = []
        for _ in range(burst_count):
            try:
                r = requests.request(method, url, json=test_payload, timeout=2)
                status_codes.append(r.status_code)
            except Exception:
                pass

        # If none of the requests triggered a 429 Too Many Requests
        if status_codes and 429 not in status_codes:
            self._record_vulnerability(
                vuln_type="Missing Rate Limiting",
                severity="Medium",
                endpoint=path,
                method=method,
                parameter="Request Bursting",
                payload_used=f"{len(status_codes)} rapid consecutive requests",
                http_status=status_codes[-1],
                evidence=f"API processed {len(status_codes)} rapid requests without enforcing rate limiting (No HTTP 429 received). Vulnerable to brute force attacks.",
                confidence=0.88,
                cwe_id="CWE-799"
            )

    # Full Scan Orchestrator
    def run_full_scan(self, endpoints: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Runs all 6 test categories across the discovered endpoints."""
        start_time = time.time()
        print(f"\n=======================================================")
        print(f"[*] STARTING AUTONOMOUS VULNERABILITY SCAN ON {self.base_url}")
        print(f"[*] Endpoints to evaluate: {len(endpoints)}")
        print(f"=======================================================\n")

        # 1. Test Security Headers
        self._progress("Checking security headers...", 30)
        self.check_security_headers()

        # 2. Iterate through endpoints
        total = max(1, len(endpoints))
        for index, ep in enumerate(endpoints, 1):
            pct = 30 + int((index - 1) / total * 45)
            self._progress(f"Testing {ep['method']} {ep['path']}...", pct)
            print(f"-> Scanning {ep['method']} {ep['path']} ...")
            # SQL Injection
            self.test_sql_injection(ep)
            # Reflected XSS
            self.test_xss(ep)
            # Authentication Testing
            self.test_authentication(ep)
            # IDOR Testing
            self.test_idor(ep)
            # Rate Limiting
            self.test_rate_limiting(ep)

        self._progress("Finalizing scan results...", 78)
        elapsed = round(time.time() - start_time, 2)
        print(f"\n[+] Scan Complete in {elapsed}s. Total vulnerabilities detected: {len(self.vulnerabilities)}")

        return {
            "target_url": self.base_url,
            "scan_duration_seconds": elapsed,
            "total_vulnerabilities": len(self.vulnerabilities),
            "findings": self.vulnerabilities
        }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Member 2 - Vulnerability Scanner Module")
    parser.add_argument("--target", default="http://127.0.0.1:8888", help="Base URL of target API")
    parser.add_argument("--spec", help="Path to OpenAPI spec file for discovery input")
    args = parser.parse_args()

    # If spec is passed, load endpoints via Member 1 discovery
    from core.discovery.api_discovery import APIDiscovery
    discovery = APIDiscovery()
    
    if args.spec:
        disc_result = discovery.load_spec_from_file(args.spec)
    else:
        # Default probe
        disc_result = discovery.probe_live_api(args.target)

    scanner = APIVulnerabilityScanner(base_url=args.target)
    scan_report = scanner.run_full_scan(disc_result["endpoints"])

    # Output JSON
    output_path = os.path.join(os.path.dirname(__file__), "..", "..", "data", "scan_results.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(scan_report, f, indent=2)

    print(f"\n[+] Scan report successfully saved to: {os.path.abspath(output_path)}")
