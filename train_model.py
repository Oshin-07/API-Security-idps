"""
Member 3: Machine Learning Model Training for Vulnerability Severity Classification
-------------------------------------------------------------------------------------
Trains a Scikit-Learn Random Forest Classifier that predicts a vulnerability's
severity (Critical/High/Medium/Low) from finding metadata.

What this script does:
1. Loads data/training_data.csv (generate it first with dataset_generator.py).
2. Vectorizes categorical + numeric features with DictVectorizer (keeps the
   same dict-in -> label-out interface that risk_engine.py relies on).
3. Trains a RandomForestClassifier inside a Pipeline.
4. Evaluates with a held-out test split AND 5-fold cross-validation.
5. Saves the trained pipeline to data/severity_model.joblib.
6. Saves ALL evaluation numbers to data/model_metrics.json so the Streamlit
   app (member3_app.py) can render them without retraining.
7. Renders and saves a set of dark/"cyber" themed PNG graphs to data/graphs/:
      - severity_distribution.png   (class balance in the training data)
      - confusion_matrix.png        (test-set prediction errors)
      - feature_importance.png      (what the model actually weighs)
      - cv_scores.png               (5-fold cross-validation stability)
      - correlation_heatmap.png     (numeric feature correlation)
"""

import os
import csv
import json
import joblib
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.feature_extraction import DictVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

# ---------------------------------------------------------------------------
# "Cyber" dark theme for every matplotlib figure this module produces
# ---------------------------------------------------------------------------
BG = "#0a0f1c"
PANEL = "#0d1526"
NEON_CYAN = "#00f5ff"
NEON_GREEN = "#39ff14"
NEON_MAGENTA = "#ff2ec4"
NEON_YELLOW = "#f6ff00"
GRID = "#1c2a44"
TEXT = "#d7f8ff"

NEON_PALETTE = [NEON_CYAN, NEON_GREEN, NEON_MAGENTA, NEON_YELLOW, "#7c4dff", "#ff8a3d"]

plt.rcParams.update({
    "figure.facecolor": BG,
    "axes.facecolor": PANEL,
    "axes.edgecolor": GRID,
    "axes.labelcolor": TEXT,
    "text.color": TEXT,
    "xtick.color": TEXT,
    "ytick.color": TEXT,
    "grid.color": GRID,
    "font.family": "monospace",
})


def load_data(csv_path):
    features, labels = [], []
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            feat = {
                "vuln_type=" + row["vuln_type"]: 1.0,
                "endpoint_sensitivity": float(row["endpoint_sensitivity"]),
                "auth_required": float(row["auth_required"]),
                "data_exposure_risk": float(row["data_exposure_risk"]),
                "attack_confidence": float(row["attack_confidence"]),
            }
            features.append(feat)
            labels.append(row["severity"])
    return features, labels


def _save_severity_distribution(labels, out_path):
    order = ["Critical", "High", "Medium", "Low"]
    counts = [labels.count(s) for s in order]
    colors = [NEON_MAGENTA, "#ff8a3d", NEON_YELLOW, NEON_GREEN]

    fig, ax = plt.subplots(figsize=(6, 4.2), dpi=150)
    bars = ax.bar(order, counts, color=colors, edgecolor=NEON_CYAN, linewidth=1.2)
    for b in bars:
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + max(counts) * 0.01,
                 str(int(b.get_height())), ha="center", color=TEXT, fontsize=9)
    ax.set_title("Training Data — Severity Class Distribution", color=NEON_CYAN, fontsize=12, pad=12)
    ax.set_ylabel("Number of samples")
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(out_path, facecolor=BG)
    plt.close(fig)


def _save_confusion_matrix(y_test, y_pred, class_order, out_path):
    cm = confusion_matrix(y_test, y_pred, labels=class_order)
    fig, ax = plt.subplots(figsize=(5.5, 4.8), dpi=150)
    cmap = sns.color_palette("mako", as_cmap=True)
    sns.heatmap(cm, annot=True, fmt="d", cmap=cmap, cbar=True,
                xticklabels=class_order, yticklabels=class_order,
                linewidths=0.6, linecolor=GRID, ax=ax,
                annot_kws={"color": "white", "fontsize": 11})
    ax.set_xlabel("Predicted severity")
    ax.set_ylabel("Actual severity")
    ax.set_title("Confusion Matrix — Held-out Test Set", color=NEON_CYAN, fontsize=12, pad=12)
    fig.tight_layout()
    fig.savefig(out_path, facecolor=BG)
    plt.close(fig)
    return cm


def _save_feature_importance(pipeline, out_path, top_n=12):
    vectorizer = pipeline.named_steps["vectorizer"]
    clf = pipeline.named_steps["classifier"]
    names = vectorizer.get_feature_names_out()
    importances = clf.feature_importances_
    order = np.argsort(importances)[::-1][:top_n]

    fig, ax = plt.subplots(figsize=(8, 5), dpi=150)
    colors = [NEON_PALETTE[i % len(NEON_PALETTE)] for i in range(len(order))]
    ax.barh([names[i] for i in order][::-1], [importances[i] for i in order][::-1],
            color=colors[::-1], edgecolor=NEON_CYAN, linewidth=0.8)
    ax.set_title("Feature Importance", color=NEON_CYAN, fontsize=13, pad=12)
    ax.set_xlabel("Relative importance (Gini)")
    ax.grid(axis="x", alpha=0.3)
    fig.tight_layout()
    fig.savefig(out_path, facecolor=BG)
    plt.close(fig)
    return {names[i]: float(importances[i]) for i in order}


def _save_cv_scores(cv_scores, out_path):
    fig, ax = plt.subplots(figsize=(6, 4.2), dpi=150)
    folds = [f"Fold {i+1}" for i in range(len(cv_scores))]
    bars = ax.bar(folds, cv_scores, color=NEON_GREEN, edgecolor=NEON_CYAN, linewidth=1.2)
    for b, v in zip(bars, cv_scores):
        ax.text(b.get_x() + b.get_width() / 2, v + 0.01, f"{v*100:.1f}%", ha="center", color=TEXT, fontsize=9)
    ax.axhline(np.mean(cv_scores), color=NEON_MAGENTA, linestyle="--", linewidth=1.4,
               label=f"Mean = {np.mean(cv_scores)*100:.1f}%")
    ax.set_ylim(0, 1.05)
    ax.set_title("5-Fold Cross-Validation Accuracy", color=NEON_CYAN, fontsize=12, pad=12)
    ax.set_ylabel("Accuracy")
    ax.legend(facecolor=PANEL, edgecolor=GRID, labelcolor=TEXT)
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(out_path, facecolor=BG)
    plt.close(fig)


def _save_correlation_heatmap(csv_path, out_path):
    import pandas as pd
    df = pd.read_csv(csv_path)
    numeric_cols = ["endpoint_sensitivity", "auth_required", "data_exposure_risk",
                     "attack_confidence", "true_risk_score"]
    numeric_cols = [c for c in numeric_cols if c in df.columns]
    corr = df[numeric_cols].corr()

    fig, ax = plt.subplots(figsize=(6, 5), dpi=150)
    cmap = sns.diverging_palette(200, 320, as_cmap=True)
    sns.heatmap(corr, annot=True, fmt=".2f", cmap=cmap, center=0, ax=ax,
                linewidths=0.6, linecolor=GRID, annot_kws={"color": "white"})
    ax.set_title("Numeric Feature Correlation", color=NEON_CYAN, fontsize=12, pad=12)
    fig.tight_layout()
    fig.savefig(out_path, facecolor=BG)
    plt.close(fig)


def train_severity_model(data_path: str, model_output_path: str, graphs_dir: str, metrics_path: str):
    print(f"[*] Loading training dataset from: {data_path}")
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Training dataset not found: {data_path}. Run dataset_generator.py first.")

    os.makedirs(graphs_dir, exist_ok=True)
    X, y = load_data(data_path)
    class_order = ["Critical", "High", "Medium", "Low"]

    pipeline = Pipeline(steps=[
        ("vectorizer", DictVectorizer(sparse=False)),
        ("classifier", RandomForestClassifier(
            n_estimators=200, max_depth=10, min_samples_leaf=3, random_state=42)),
    ])

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y)
    print(f"[*] Training samples: {len(X_train)}, Testing samples: {len(X_test)}")

    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    report_dict = classification_report(y_test, y_pred, output_dict=True, zero_division=0)

    print("\n=======================================================")
    print(f"[+] MODEL TRAINING COMPLETE. Test Accuracy: {accuracy * 100:.2f}%")
    print("=======================================================\n")
    print(classification_report(y_test, y_pred, zero_division=0))

    # 5-fold stratified cross-validation for a more honest accuracy estimate
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(pipeline, X, y, cv=skf, scoring="accuracy")
    print(f"[*] 5-Fold CV Accuracy: {cv_scores.mean()*100:.2f}% (+/- {cv_scores.std()*100:.2f}%)")

    # --- Graphs ---
    _save_severity_distribution(y, os.path.join(graphs_dir, "severity_distribution.png"))
    cm = _save_confusion_matrix(y_test, y_pred, class_order, os.path.join(graphs_dir, "confusion_matrix.png"))
    top_features = _save_feature_importance(pipeline, os.path.join(graphs_dir, "feature_importance.png"))
    _save_cv_scores(cv_scores, os.path.join(graphs_dir, "cv_scores.png"))
    _save_correlation_heatmap(data_path, os.path.join(graphs_dir, "correlation_heatmap.png"))
    print(f"[+] Evaluation graphs saved to: {graphs_dir}")

    # --- Persist model + metrics ---
    os.makedirs(os.path.dirname(model_output_path), exist_ok=True)
    joblib.dump(pipeline, model_output_path)
    print(f"[+] Trained ML pipeline saved to: {model_output_path}")

    metrics = {
        "test_accuracy": round(accuracy, 4),
        "cv_mean_accuracy": round(float(cv_scores.mean()), 4),
        "cv_std_accuracy": round(float(cv_scores.std()), 4),
        "cv_fold_scores": [round(float(s), 4) for s in cv_scores],
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "total_samples": len(X),
        "class_order": class_order,
        "confusion_matrix": cm.tolist(),
        "classification_report": report_dict,
        "top_feature_importance": top_features,
        "model_params": {
            "n_estimators": 200,
            "max_depth": 10,
            "min_samples_leaf": 3,
        },
    }
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"[+] Model metrics saved to: {metrics_path}")

    return metrics


if __name__ == "__main__":
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    csv_file = os.path.join(base_dir, "data", "training_data.csv")
    model_file = os.path.join(base_dir, "data", "severity_model.joblib")
    graphs_folder = os.path.join(base_dir, "data", "graphs")
    metrics_file = os.path.join(base_dir, "data", "model_metrics.json")
    train_severity_model(csv_file, model_file, graphs_folder, metrics_file)
