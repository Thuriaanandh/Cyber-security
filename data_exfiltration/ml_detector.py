"""
ml_detector.py — Stage 7: Machine-learning based detection.

Two complementary models are used:

1. RandomForestClassifier — supervised (requires labelled training data).
   Labels: 'benign', 'suspicious', 'exfiltration'

2. IsolationForest — unsupervised anomaly detection.
   Works even without labels; flags statistical outliers.
"""

from __future__ import annotations
import os
import pickle
from typing import Tuple, Optional

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

from feature_extractor import FEATURE_COLUMNS
from utils import setup_logger, ensure_dir

logger = setup_logger(__name__)

MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
RF_MODEL_PATH = os.path.join(MODEL_DIR, "rf_model.pkl")
IF_MODEL_PATH = os.path.join(MODEL_DIR, "if_model.pkl")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

def train_models(
    df: pd.DataFrame,
    save: bool = True,
) -> Tuple[RandomForestClassifier, IsolationForest, StandardScaler]:
    """
    Train both models on *df*.

    Args:
        df:   DataFrame with FEATURE_COLUMNS and a 'label' column.
              Expected labels: 'benign', 'suspicious', 'exfiltration'.
        save: If True, persist models to disk.

    Returns:
        (rf_model, if_model, scaler)
    """
    # Validate columns
    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Training DataFrame missing columns: {missing}")
    if "label" not in df.columns:
        raise ValueError("Training DataFrame must contain a 'label' column.")

    X = df[FEATURE_COLUMNS].fillna(0).values
    y = df["label"].values

    # Feature scaling
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # ── RandomForest ──────────────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )

    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    rf.fit(X_train, y_train)

    y_pred = rf.predict(X_test)
    logger.info("RandomForest training report:\n%s",
                classification_report(y_test, y_pred, zero_division=0))

    # ── IsolationForest ───────────────────────────────────────────────────
    # Train on all data (unsupervised); contamination ≈ expected anomaly rate
    contamination = max(0.01, (df["label"] != "benign").mean())
    contamination = min(contamination, 0.4)   # sklearn upper bound

    iso = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=42,
        n_jobs=-1,
    )
    iso.fit(X_scaled)
    logger.info("IsolationForest trained (contamination=%.2f)", contamination)

    # ── Persist ───────────────────────────────────────────────────────────
    if save:
        ensure_dir(MODEL_DIR)
        with open(RF_MODEL_PATH, "wb") as f:
            pickle.dump(rf, f)
        with open(IF_MODEL_PATH, "wb") as f:
            pickle.dump(iso, f)
        with open(SCALER_PATH, "wb") as f:
            pickle.dump(scaler, f)
        logger.info("Models saved to %s", MODEL_DIR)

    return rf, iso, scaler


# ---------------------------------------------------------------------------
# Loading persisted models
# ---------------------------------------------------------------------------

def load_models() -> Tuple[
    Optional[RandomForestClassifier],
    Optional[IsolationForest],
    Optional[StandardScaler],
]:
    """Load previously saved models from disk. Returns None for missing files."""
    rf = iso = scaler = None

    for path, name in [
        (RF_MODEL_PATH, "RandomForest"),
        (IF_MODEL_PATH, "IsolationForest"),
        (SCALER_PATH, "Scaler"),
    ]:
        if not os.path.isfile(path):
            logger.warning("%s model not found at %s — run train_models first.", name, path)

    try:
        with open(RF_MODEL_PATH, "rb") as f:
            rf = pickle.load(f)
        with open(IF_MODEL_PATH, "rb") as f:
            iso = pickle.load(f)
        with open(SCALER_PATH, "rb") as f:
            scaler = pickle.load(f)
        logger.info("Models loaded from %s", MODEL_DIR)
    except Exception as exc:
        logger.error("Failed to load models: %s", exc)

    return rf, iso, scaler


# ---------------------------------------------------------------------------
# Inference
# ---------------------------------------------------------------------------

def predict(
    df: pd.DataFrame,
    rf: Optional[RandomForestClassifier] = None,
    iso: Optional[IsolationForest] = None,
    scaler: Optional[StandardScaler] = None,
) -> pd.DataFrame:
    """
    Run ML predictions on *df*.

    Adds columns:
        rf_label          — RandomForest class prediction
        rf_confidence     — probability of the predicted class
        if_anomaly        — 1=anomaly, 0=normal (IsolationForest)
        if_anomaly_score  — raw anomaly score (more negative = more anomalous)
        ml_label          — combined final label

    Args:
        df:     Feature DataFrame (must contain FEATURE_COLUMNS).
        rf, iso, scaler: Pre-loaded models (loaded from disk if None).

    Returns:
        DataFrame with ML prediction columns appended.
    """
    if rf is None or iso is None or scaler is None:
        rf, iso, scaler = load_models()

    if rf is None:
        logger.warning("Models unavailable — skipping ML detection.")
        df = df.copy()
        df["rf_label"] = "unknown"
        df["rf_confidence"] = 0.0
        df["if_anomaly"] = 0
        df["if_anomaly_score"] = 0.0
        df["ml_label"] = "unknown"
        return df

    X = df[FEATURE_COLUMNS].fillna(0).values
    X_scaled = scaler.transform(X)

    # RandomForest prediction
    rf_preds = rf.predict(X_scaled)
    rf_proba = rf.predict_proba(X_scaled)
    rf_confidence = rf_proba.max(axis=1)

    # IsolationForest anomaly detection
    # predict returns  1 (normal) or -1 (anomaly)
    if_preds = iso.predict(X_scaled)
    if_scores = iso.score_samples(X_scaled)
    if_anomaly = (if_preds == -1).astype(int)

    # Combined label: escalate to Possible Exfiltration if either model flags
    def combine_labels(rf_label: str, anomaly: int) -> str:
        if rf_label == "exfiltration":
            return "Possible Exfiltration"
        if rf_label == "suspicious" or anomaly == 1:
            return "Suspicious"
        return "Benign"

    df = df.copy()
    df["rf_label"] = rf_preds
    df["rf_confidence"] = rf_confidence.round(4)
    df["if_anomaly"] = if_anomaly
    df["if_anomaly_score"] = if_scores.round(6)
    df["ml_label"] = [
        combine_labels(r, a) for r, a in zip(rf_preds, if_anomaly)
    ]

    flagged = (df["ml_label"] != "Benign").sum()
    logger.info("ML detection complete — %d / %d flows flagged", flagged, len(df))
    return df
