"""
Member 3: AI/ML Risk Assessment and Scoring Engine
Orchestrates:
1. ML Severity Prediction using trained Scikit-Learn Model.
2. Endpoint Sensitivity and Data Exposure scoring.
3. System-Wide Dynamic Risk Score (0-100) and CVSS 3.1 Base Score estimation.
4. Natural Language Explanation generation and Remediation suggestions.
5. Adaptive Attack Simulation strategy formulation.
"""

import sys
import os
import json
import argparse
from typing import Dict, List, Any
import joblib

# Add parent directory to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from core.ai_risk.explanation_engine import ExplanationEngine
from core.ai_risk.adaptive_selector import AdaptiveAttackSelector

class AIRiskAssessmentEngine:
    def __init__(self, model_path: str = None):
        if model_path is None:
            model_path = os.path.join(os.path.dirname(__file__), "..", "..", "data", "severity_model.joblib")
        self.model_path = os.path.abspath(model_path)
        self.ml_model = None
        self._load_model()
        self.explainer = ExplanationEngine()
        self.adaptive_selector = AdaptiveAttackSelector()

    def _load_model(self):
        """Loads trained Scikit-Learn pipeline."""
        if os.path.exists(self.model_path):
            try:
                self.ml_model = joblib.load(self.model_path)
                print(f"[+] Loaded ML Severity Prediction model from: {self.model_path}")
            except Exception as e:
                print(f"[!] Warning: Could not load ML model: {e}")
        else:
            print(f"[!] ML model not found at {self.model_path}. Run train_model.py first.")

    def compute_endpoint_sensitivity(self, endpoint: str) -> int:
        """Assigns sensitivity weight (1-5) based on endpoint path semantics."""
        ep_lower = endpoint.lower()
        if any(k in ep_lower for k in ["admin", "root", "auth", "login", "secret", "token"]):
            return 5
        if any(k in ep_lower for k in ["payment", "billing", "card", "checkout"]):
            return 5
        if any(k in ep_lower for k in ["user", "profile", "account", "order"]):
            return 4
        if any(k in ep_lower for k in ["comment", "search", "upload", "message"]):
            return 3
        if any(k in ep_lower for k in ["health", "status", "docs", "ping"]):
            return 1
        return 2

    def compute_data_exposure(self, evidence: str, param: str) -> int:
        """Assigns data exposure risk (1-5) based on captured evidence and parameter names."""
        text = (evidence + " " + param).lower()
        if any(k in text for k in ["password", "secret", "ssn", "token", "credit", "jwt"]):
            return 5
        if any(k in text for k in ["email", "phone", "profile", "address", "database"]):
            return 4
        if any(k in text for k in ["user", "role", "id", "status"]):
            return 3
        return 1

    def assess_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Processes scan findings with ML prediction, risk scoring, explanations, and adaptive attacks.
        """
        enriched_findings = []
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        total_weighted_risk = 0.0

        SEVERITY_WEIGHTS = {
            "Critical": 25.0,
            "High": 15.0,
            "Medium": 8.0,
            "Low": 2.5
        }

        for f in findings:
            v_type = f.get("vulnerability_type", "Unknown")
            endpoint = f.get("endpoint", "")
            param = f.get("parameter", "")
            evidence = f.get("evidence", "")
            confidence = float(f.get("confidence", 0.90))

            # Compute features
            sensitivity = self.compute_endpoint_sensitivity(endpoint)
            data_exposure = self.compute_data_exposure(evidence, param)
            auth_req = 1 if "auth" in endpoint.lower() or "admin" in endpoint.lower() else 0

            # Normalize vulnerability type key for ML model
            ml_type_map = {
                "sql injection": "SQL_Injection",
                "xss": "Reflected_XSS",
                "broken authentication": "Broken_Authentication",
                "idor": "IDOR",
                "missing rate limiting": "Missing_Rate_Limiting",
                "missing security header": "Missing_Security_Headers",
                "permissive cors": "Missing_Security_Headers"
            }
            mapped_type = "SQL_Injection"
            for k, v in ml_type_map.items():
                if k in v_type.lower():
                    mapped_type = v
                    break

            # Predict severity using Scikit-Learn Model if available
            predicted_severity = f.get("severity", "Medium")
            if self.ml_model:
                try:
                    feat_dict = {
                        f"vuln_type={mapped_type}": 1.0,
                        "endpoint_sensitivity": float(sensitivity),
                        "auth_required": float(auth_req),
                        "data_exposure_risk": float(data_exposure),
                        "attack_confidence": float(confidence)
                    }
                    pred = self.ml_model.predict([feat_dict])[0]
                    predicted_severity = pred
                except Exception as e:
                    pass

            severity_counts[predicted_severity] = severity_counts.get(predicted_severity, 0) + 1

            # Individual Risk Impact Contribution
            base_w = SEVERITY_WEIGHTS.get(predicted_severity, 10.0)
            finding_risk = base_w * (sensitivity / 3.0) * confidence
            total_weighted_risk += finding_risk

            # Generate natural language explanation
            explanation = self.explainer.explain_vulnerability({
                **f,
                "severity": predicted_severity
            })

            enriched_record = {
                "id": f.get("id"),
                "vulnerability_type": v_type,
                "original_severity": f.get("severity"),
                "ml_predicted_severity": predicted_severity,
                "endpoint": endpoint,
                "method": f.get("method"),
                "parameter": param,
                "payload_used": f.get("payload_used"),
                "confidence": confidence,
                "factors": {
                    "endpoint_sensitivity_score": sensitivity,
                    "data_exposure_score": data_exposure,
                    "auth_requirement_factor": auth_req
                },
                "explanation": explanation
            }
            enriched_findings.append(enriched_record)

        # Calculate Overall Risk Score (0-100)
        overall_risk_score = round(min(100.0, total_weighted_risk), 1)

        # Estimate CVSS 3.1 Base Score (0.0 - 10.0)
        if severity_counts["Critical"] > 0:
            cvss_base = round(min(10.0, 9.0 + (severity_counts["Critical"] * 0.3)), 1)
        elif severity_counts["High"] > 0:
            cvss_base = round(min(8.9, 7.0 + (severity_counts["High"] * 0.4)), 1)
        elif severity_counts["Medium"] > 0:
            cvss_base = round(min(6.9, 4.0 + (severity_counts["Medium"] * 0.5)), 1)
        else:
            cvss_base = round(min(3.9, severity_counts["Low"] * 0.5), 1)

        # Threat Level
        if overall_risk_score >= 70:
            threat_level = "CRITICAL"
        elif overall_risk_score >= 45:
            threat_level = "HIGH"
        elif overall_risk_score >= 20:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"

        # Adaptive Attack Simulation Plan
        adaptive_attack_plan = self.adaptive_selector.analyze_and_adapt(findings)

        assessment_result = {
            "overall_risk_score": overall_risk_score,
            "threat_level": threat_level,
            "cvss_base_score": cvss_base,
            "total_findings": len(findings),
            "severity_breakdown": severity_counts,
            "enriched_findings": enriched_findings,
            "adaptive_attack_plan": adaptive_attack_plan
        }

        # Generate Executive Summary
        assessment_result["executive_summary"] = self.explainer.generate_executive_summary(assessment_result)
        return assessment_result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Member 3 - AI/ML Risk Assessment Module")
    parser.add_argument("--scan-file", default="data/scan_results.json", help="Path to vulnerability scan JSON")
    args = parser.parse_args()

    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    scan_file_path = os.path.join(base_dir, args.scan_file) if not os.path.isabs(args.scan_file) else args.scan_file

    if not os.path.exists(scan_file_path):
        print(f"[!] Scan results file not found at: {scan_file_path}")
        print("[!] Generating sample test findings for demonstration...")
        sample_findings = [
            {
                "id": "VULN-001",
                "vulnerability_type": "SQL Injection",
                "severity": "Critical",
                "endpoint": "/api/users/search",
                "method": "GET",
                "parameter": "query",
                "payload_used": "' OR '1'='1",
                "evidence": "sqlite3.OperationalError: syntax error near '1'",
                "confidence": 0.98,
                "cwe_id": "CWE-89"
            },
            {
                "id": "VULN-002",
                "vulnerability_type": "Reflected Cross-Site Scripting (XSS)",
                "severity": "High",
                "endpoint": "/api/comments",
                "method": "POST",
                "parameter": "comment",
                "payload_used": "<script>alert('XSS')</script>",
                "evidence": "Payload reflected unescaped in rendered_html",
                "confidence": 0.95,
                "cwe_id": "CWE-79"
            }
        ]
    else:
        with open(scan_file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            sample_findings = data.get("findings", [])

    engine = AIRiskAssessmentEngine()
    result = engine.assess_findings(sample_findings)

    print("\n" + "=" * 55)
    print("AI RISK ASSESSMENT RESULTS")
    print("=" * 55)
    print(f"Overall Risk Score: {result['overall_risk_score']}/100")
    print(f"Threat Level:       {result['threat_level']}")
    print(f"CVSS Base Score:    {result['cvss_base_score']}/10.0")
    print(f"Total Findings:     {result['total_findings']}")
    print(f"Severity Breakdown: {result['severity_breakdown']}")
    print("=" * 55)
    print("\n" + result["executive_summary"])

    # Save to disk
    out_file = os.path.join(base_dir, "data", "risk_assessment_report.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    print(f"\n[+] Full risk assessment report saved to: {out_file}")
