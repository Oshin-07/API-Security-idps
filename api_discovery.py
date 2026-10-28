"""
Member 1: API Discovery Module
------------------------------
Responsibilities:
1. Accept API Base URL or Swagger/OpenAPI file (JSON / YAML) / URL.
2. Discover and catalog all API endpoints.
3. Identify HTTP methods (GET, POST, PUT, DELETE, PATCH).
4. Extract parameters (query, path, header), data types, body schemas, and authentication schemes.
5. Provide structured JSON output ready for Vulnerability Scanner and Backend orchestration.
"""

import json
import os
import argparse
from typing import Dict, List, Any, Optional
import requests
import yaml

class APIDiscovery:
    def __init__(self):
        self.discovered_endpoints: List[Dict[str, Any]] = []
        self.api_info: Dict[str, Any] = {}
        self.base_url: str = ""

    def load_spec_from_file(self, file_path: str) -> Dict[str, Any]:
        """Loads and parses an OpenAPI / Swagger file from local disk (JSON or YAML)."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Specification file not found at: {file_path}")
        
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
            try:
                spec = json.loads(content)
            except json.JSONDecodeError:
                spec = yaml.safe_load(content)
        return self.parse_openapi_spec(spec)

    def load_spec_from_url(self, spec_url: str) -> Dict[str, Any]:
        """Fetches OpenAPI / Swagger specification from a live HTTP/HTTPS URL."""
        response = requests.get(spec_url, timeout=10)
        response.raise_for_status()
        try:
            spec = response.json()
        except ValueError:
            spec = yaml.safe_load(response.text)
        return self.parse_openapi_spec(spec)

    def parse_openapi_spec(self, spec: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parses OpenAPI 2.0 (Swagger) and OpenAPI 3.0.x specifications.
        Extracts endpoints, HTTP methods, parameters, types, and auth mechanisms.
        """
        self.api_info = {
            "title": spec.get("info", {}).get("title", "Unknown API"),
            "version": spec.get("info", {}).get("version", "1.0"),
            "description": spec.get("info", {}).get("description", "")
        }

        # Resolve Base URL
        if "servers" in spec and len(spec["servers"]) > 0:
            self.base_url = spec["servers"][0].get("url", "")
        elif "host" in spec:
            scheme = spec.get("schemes", ["http"])[0]
            base_path = spec.get("basePath", "")
            self.base_url = f"{scheme}://{spec['host']}{base_path}"
        else:
            self.base_url = "http://localhost:5000"

        # Global Security Schemes
        security_schemes = {}
        if "components" in spec and "securitySchemes" in spec["components"]:
            security_schemes = spec["components"]["securitySchemes"]
        elif "securityDefinitions" in spec:
            security_schemes = spec["securityDefinitions"]

        paths = spec.get("paths", {})
        endpoints_list = []

        valid_methods = ["get", "post", "put", "delete", "patch", "options", "head"]

        for path, path_item in paths.items():
            # Path-level parameters
            path_level_params = path_item.get("parameters", [])

            for method, operation in path_item.items():
                if method.lower() not in valid_methods:
                    continue

                operation_id = operation.get("operationId", f"{method.upper()}_{path}")
                summary = operation.get("summary", "")

                # Determine authentication requirement
                operation_security = operation.get("security", spec.get("security", []))
                auth_required = len(operation_security) > 0
                auth_types = []
                if auth_required:
                    for sec in operation_security:
                        for scheme_name in sec.keys():
                            scheme_info = security_schemes.get(scheme_name, {})
                            auth_types.append({
                                "scheme": scheme_name,
                                "type": scheme_info.get("type", "unknown"),
                                "in": scheme_info.get("in", "header")
                            })

                # Parameters extraction
                parameters = []
                all_params = path_level_params + operation.get("parameters", [])
                for param in all_params:
                    # Handle param schemas
                    p_type = "string"
                    if "schema" in param and "type" in param["schema"]:
                        p_type = param["schema"]["type"]
                    elif "type" in param:
                        p_type = param["type"]

                    parameters.append({
                        "name": param.get("name"),
                        "in": param.get("in"),  # query, path, header, cookie
                        "required": param.get("required", False),
                        "type": p_type,
                        "description": param.get("description", "")
                    })

                # Request Body Extraction (OpenAPI 3.0)
                body_schema = {}
                request_body = operation.get("requestBody", {})
                if request_body and "content" in request_body:
                    for content_type, content_info in request_body["content"].items():
                        raw_schema = content_info.get("schema", {})
                        body_schema = {
                            "content_type": content_type,
                            "properties": raw_schema.get("properties", {}),
                            "required_fields": raw_schema.get("required", [])
                        }
                        break

                endpoint_record = {
                    "path": path,
                    "method": method.upper(),
                    "summary": summary,
                    "operation_id": operation_id,
                    "parameters": parameters,
                    "body_schema": body_schema,
                    "auth_required": auth_required,
                    "auth_types": auth_types
                }
                endpoints_list.append(endpoint_record)

        self.discovered_endpoints = endpoints_list
        return {
            "api_info": self.api_info,
            "base_url": self.base_url,
            "total_endpoints": len(self.discovered_endpoints),
            "endpoints": self.discovered_endpoints
        }

    def probe_live_api(self, base_url: str) -> Dict[str, Any]:
        """
        Active discovery: Attempts to locate OpenAPI spec at standard routes.
        If not found, executes active probing of common API endpoints.
        """
        self.base_url = base_url.rstrip("/")
        spec_routes = ["/openapi.json", "/swagger.json", "/api/openapi.json", "/v2/api-docs"]

        for route in spec_routes:
            candidate_url = f"{self.base_url}{route}"
            try:
                resp = requests.get(candidate_url, timeout=3)
                if resp.status_code == 200:
                    try:
                        spec = resp.json()
                        if "paths" in spec:
                            print(f"[+] Found live OpenAPI spec at {candidate_url}")
                            return self.parse_openapi_spec(spec)
                    except Exception:
                        pass
            except Exception:
                continue

        # Fallback: Heuristic probing
        print("[!] No OpenAPI spec discovered automatically. Running heuristic endpoint discovery...")
        common_probes = [
            {"path": "/api/health", "method": "GET"},
            {"path": "/api/users", "method": "GET"},
            {"path": "/api/users/search", "method": "GET", "parameters": [{"name": "query", "in": "query", "type": "string"}]},
            {"path": "/api/comments", "method": "POST"},
            {"path": "/api/login", "method": "POST"},
            {"path": "/api/admin", "method": "GET"},
            {"path": "/api/profile/101", "method": "GET"}
        ]

        discovered = []
        for probe in common_probes:
            test_url = f"{self.base_url}{probe['path']}"
            try:
                r = requests.request(probe["method"], test_url, timeout=2)
                if r.status_code != 404:
                    discovered.append({
                        "path": probe["path"],
                        "method": probe["method"],
                        "summary": f"Discovered via active probe (Status {r.status_code})",
                        "parameters": probe.get("parameters", []),
                        "body_schema": {},
                        "auth_required": r.status_code in [401, 403],
                        "auth_types": [{"scheme": "unknown", "type": "heuristic"}] if r.status_code in [401, 403] else []
                    })
            except Exception:
                continue

        self.discovered_endpoints = discovered
        return {
            "api_info": {"title": "Heuristically Probed API", "version": "1.0"},
            "base_url": self.base_url,
            "total_endpoints": len(discovered),
            "endpoints": discovered
        }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Member 1 - API Discovery Module")
    parser.add_argument("--spec", help="Path to OpenAPI / Swagger JSON or YAML file")
    parser.add_argument("--url", help="URL of live OpenAPI specification")
    parser.add_argument("--probe", help="Base URL of live API to probe (e.g. http://127.0.0.1:5000)")
    args = parser.parse_args()

    discovery = APIDiscovery()
    result = None

    if args.spec:
        print(f"[*] Discovering endpoints from local spec file: {args.spec}")
        result = discovery.load_spec_from_file(args.spec)
    elif args.url:
        print(f"[*] Discovering endpoints from spec URL: {args.url}")
        result = discovery.load_spec_from_url(args.url)
    elif args.probe:
        print(f"[*] Probing live API at: {args.probe}")
        result = discovery.probe_live_api(args.probe)
    else:
        # Default self-test using sample_openapi.json
        sample_path = os.path.join(os.path.dirname(__file__), "..", "..", "test_vulnerable_api", "sample_openapi.json")
        sample_path = os.path.abspath(sample_path)
        print(f"[*] Running self-test using: {sample_path}")
        result = discovery.load_spec_from_file(sample_path)

    print("\n--- DISCOVERY SUMMARY ---")
    print(f"API Title: {result['api_info'].get('title')}")
    print(f"Base URL:  {result.get('base_url')}")
    print(f"Discovered Endpoints: {result.get('total_endpoints')}")
    print("-------------------------\n")
    for ep in result["endpoints"]:
        auth_tag = "[AUTH REQUIRED]" if ep["auth_required"] else "[PUBLIC]"
        params_info = f", Params: {[p['name'] for p in ep['parameters']]}" if ep["parameters"] else ""
        print(f"-> {ep['method']} {ep['path']} {auth_tag}{params_info}")
