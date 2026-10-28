"""
End-to-End Pipeline Runner
Runs:
1. Member 1: API Discovery
2. Member 2: Vulnerability Scanner
3. Member 3: AI/ML Risk Assessment & Adaptive Attack Simulation
Prints a comprehensive security assessment report to console and saves JSON report.
"""

import os
import sys
import json
import argparse

sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from core.discovery.api_discovery import APIDiscovery
from core.scanner.vuln_scanner import APIVulnerabilityScanner
from core.ai_risk.risk_engine import AIRiskAssessmentEngine

def run_pipeline(target_url: str, spec_path: str = None, spec_url: str = None):
    print("=" * 65)
    print(" AI-DRIVEN ADAPTIVE API SECURITY SCANNER ")
    print(" Autonomous Attack Simulation & Intelligent Risk Assessment ")
    print("=" * 65)
    print(f"[*] Target URL: {target_url}\n")

    # PHASE 1: MEMBER 1 - API DISCOVERY
    print("[PHASE 1] MEMBER 1: Running API Discovery...")
    discovery = APIDiscovery()
    if spec_path:
        disc_res = discovery.load_spec_from_file(spec_path)
    elif spec_url:
        disc_res = discovery.load_spec_from_url(spec_url)
    else:
        disc_res = discovery.probe_live_api(target_url)

    print(f"[+] Discovery Complete. Found {disc_res['total_endpoints']} endpoints.")
    for ep in disc_res["endpoints"]:
        print(f"    - {ep['method']:<6} {ep['path']}")

    # PHASE 2: MEMBER 2 - VULNERABILITY SCANNER
    print("\n[PHASE 2] MEMBER 2: Autonomous Vulnerability Testing...")
    scanner = APIVulnerabilityScanner(base_url=target_url)
    scan_res = scanner.run_full_scan(disc_res["endpoints"])
    print(f"[+] Scan Complete. Detected {scan_res['total_vulnerabilities']} potential vulnerabilities.")

    # PHASE 3: MEMBER 3 - AI/ML RISK ASSESSMENT
    print("\n[PHASE 3] MEMBER 3: AI/ML Risk Assessment & Adaptive Simulation...")
    risk_engine = AIRiskAssessmentEngine()
    assessment = risk_engine.assess_findings(scan_res["findings"])

    print("\n" + "=" * 65)
    print(" FINAL SECURITY AUDIT & RISK REPORT ")
    print("=" * 65)
    print(f"Target Service:             {target_url}")
    print(f"Discovered Endpoints:       {disc_res['total_endpoints']}")
    print(f"Total Detected Issues:      {scan_res['total_vulnerabilities']}")
    print(f"Overall System Risk Score:  {assessment['overall_risk_score']} / 100")
    print(f"Calculated Threat Level:    {assessment['threat_level']}")
    print(f"Estimated CVSS Base Score:  {assessment['cvss_base_score']} / 10.0")
    print(f"Severity Distribution:      {assessment['severity_breakdown']}")
    print("-" * 65)
    print("\n" + assessment["executive_summary"])

    print("\n[*] VULNERABILITY DETAILS & REMEDIATION:")
    for f in assessment["enriched_findings"]:
        print(f"\n[{f['ml_predicted_severity'].upper()}] {f['vulnerability_type']} on {f['method']} {f['endpoint']}")
        print(f"  Parameter:   {f['parameter']}")
        print(f"  Payload:     {f['payload_used']}")
        print(f"  Confidence:  {f['confidence'] * 100:.0f}%")
        exp = f.get("explanation", {})
        print(f"  Impact:      {exp.get('attack_impact')}")
        print(f"  Remediation: {exp.get('remediation_guidance')}")

    print("\n" + "=" * 65)
    print(" AUTONOMOUS ADAPTIVE ATTACK SIMULATION PLAN (NEXT STAGE) ")
    print("=" * 65)
    plans = assessment.get("adaptive_attack_plan", {}).get("adaptive_attack_plans", [])
    if not plans:
        print("No secondary adaptive attacks required.")
    for idx, p in enumerate(plans, 1):
        print(f"{idx}. Target: {p['method']} {p['endpoint']}")
        print(f"   Strategy:  {p.get('strategy', 'Targeted Payload Adaptation')}")
        print(f"   Target DB: {p.get('target_db', 'N/A')}")
        print(f"   Rationale: {p.get('rationale', '')}")
        print(f"   Tailored Payloads: {p.get('adaptive_payloads', [])}")

    # Save to disk
    report_file = os.path.join(os.path.dirname(__file__), "data", "final_assessment_report.json")
    complete_report = {
        "target_url": target_url,
        "discovery": disc_res,
        "scan": scan_res,
        "assessment": assessment
    }
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(complete_report, f, indent=2)
    print(f"\n[+] Full report saved to: {os.path.abspath(report_file)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Full Security Scanner Pipeline")
    parser.add_argument("--target", default="http://127.0.0.1:5000", help="Base URL of target API")
    parser.add_argument("--spec", help="Path to local OpenAPI spec file")
    parser.add_argument("--spec-url", help="URL of OpenAPI spec")
    args = parser.parse_args()

    run_pipeline(target_url=args.target, spec_path=args.spec, spec_url=args.spec_url)
