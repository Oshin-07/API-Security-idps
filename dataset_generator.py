"""
Member 3: Training Dataset Generator for API Vulnerability Severity Prediction
-------------------------------------------------------------------------------
There is no public, labelled dataset that maps "API vulnerability finding
metadata -> severity label" (this is a narrow, internal-tooling problem, not
a general security dataset like NSL-KDD/CICIDS, which are for network
intrusion detection, not API-level findings). The academically accepted
approach for this exact situation is to build a SIMULATED dataset whose
labels come from a defensible scoring rule instead of pure random guessing.

So instead of randomly assigning severities, this generator:
1. Grounds every label in the same logic real-world CVSS 3.1 scoring uses:
   vulnerability type base severity + endpoint sensitivity + data exposure
   + authentication context + attacker confidence.
2. Computes a continuous 0-100 "true risk score" from those factors.
3. Buckets that score into Critical/High/Medium/Low using CVSS-style cut-offs.
4. Injects small, controlled label noise (~6%) and feature jitter so the
   dataset behaves like real-world security telemetry (imperfect, slightly
   ambiguous cases) rather than a trivial lookup table a model could
   memorize to 100% accuracy.

Features (must match what risk_engine.py computes at inference time):
    vuln_type            : one of 6 OWASP API Top-10 style categories
    endpoint_sensitivity : 1 (public/info) .. 5 (admin/financial)
    auth_required        : 0 or 1
    data_exposure_risk   : 1 (none) .. 5 (credentials/PII)
    attack_confidence    : 0.50 .. 1.00 (scanner confidence in the finding)

Label:
    severity : Critical | High | Medium | Low
"""

import os
import random
import csv

RANDOM_SEED = 42

VULN_PROFILES = {
    # base_weight approximates a CVSS "attack impact" starting point
    "SQL_Injection": {
        "base_weight": 9.0,
        "sensitivity_range": (2, 5),
        "exposure_range": (3, 5),
        "confidence_range": (0.85, 1.0),
        "auth_bias": 0.5,
    },
    "Broken_Authentication": {
        "base_weight": 8.5,
        "sensitivity_range": (3, 5),
        "exposure_range": (3, 5),
        "confidence_range": (0.80, 1.0),
        "auth_bias": 1.0,
    },
    "IDOR": {
        "base_weight": 6.5,
        "sensitivity_range": (2, 4),
        "exposure_range": (2, 4),
        "confidence_range": (0.75, 0.95),
        "auth_bias": 0.5,
    },
    "Reflected_XSS": {
        "base_weight": 5.5,
        "sensitivity_range": (1, 4),
        "exposure_range": (1, 3),
        "confidence_range": (0.70, 0.98),
        "auth_bias": 0.5,
    },
    "Missing_Rate_Limiting": {
        "base_weight": 4.5,
        "sensitivity_range": (2, 5),
        "exposure_range": (1, 3),
        "confidence_range": (0.70, 0.95),
        "auth_bias": 0.4,
    },
    "Missing_Security_Headers": {
        "base_weight": 2.5,
        "sensitivity_range": (1, 3),
        "exposure_range": (1, 2),
        "confidence_range": (0.90, 1.0),
        "auth_bias": 0.3,
    },
}


def _bucket_severity(score: float) -> str:
    """CVSS 3.1-style qualitative bucketing of a 0-100 continuous risk score."""
    if score >= 72:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 28:
        return "Medium"
    return "Low"


def generate_synthetic_dataset(num_samples: int = 1500, output_file: str = "data/training_data.csv",
                                noise_rate: float = 0.06, seed: int = RANDOM_SEED):
    rng = random.Random(seed)
    vuln_types = list(VULN_PROFILES.keys())
    records = []

    for _ in range(num_samples):
        v_type = rng.choice(vuln_types)
        profile = VULN_PROFILES[v_type]

        sensitivity = rng.randint(*profile["sensitivity_range"])
        data_exposure = rng.randint(*profile["exposure_range"])
        confidence = round(rng.uniform(*profile["confidence_range"]), 2)
        auth_req = 1 if rng.random() < profile["auth_bias"] else 0

        # --- Continuous "ground truth" risk score (0-100), CVSS-inspired ---
        score = (
            profile["base_weight"] * 6.0      # up to ~54 pts from vuln class
            + sensitivity * 5.0                 # up to 25 pts
            + data_exposure * 4.0               # up to 20 pts
            + auth_req * 4.0                     # up to 4 pts
            + (confidence - 0.5) * 10.0          # up to 5 pts
        )
        # Small jitter (sum of uniforms ~ approximates a bell curve) so the
        # boundary between classes isn't a hard, memorizable cutoff.
        jitter = (rng.uniform(-1, 1) + rng.uniform(-1, 1) + rng.uniform(-1, 1)) * 3.0
        score = max(0.0, min(100.0, score + jitter))

        severity = _bucket_severity(score)

        # --- Controlled label noise: occasionally shift one severity band ---
        if rng.random() < noise_rate:
            bands = ["Low", "Medium", "High", "Critical"]
            idx = bands.index(severity)
            shift = rng.choice([-1, 1])
            severity = bands[max(0, min(len(bands) - 1, idx + shift))]

        records.append({
            "vuln_type": v_type,
            "endpoint_sensitivity": sensitivity,
            "auth_required": auth_req,
            "data_exposure_risk": data_exposure,
            "attack_confidence": confidence,
            "true_risk_score": round(score, 1),
            "severity": severity,
        })

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "vuln_type",
            "endpoint_sensitivity",
            "auth_required",
            "data_exposure_risk",
            "attack_confidence",
            "true_risk_score",
            "severity",
        ])
        writer.writeheader()
        writer.writerows(records)

    print(f"[+] Generated {num_samples} training records -> {output_file}")
    dist = {}
    for r in records:
        dist[r["severity"]] = dist.get(r["severity"], 0) + 1
    print(f"[i] Class distribution: {dist}")
    return output_file


if __name__ == "__main__":
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    out_csv = os.path.join(base_dir, "data", "training_data.csv")
    generate_synthetic_dataset(num_samples=1500, output_file=out_csv)
