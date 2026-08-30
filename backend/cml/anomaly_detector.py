"""
Isolation Forest Anomaly Detector for ICDS-H.

This module provides an unsupervised anomaly detection layer using
sklearn's Isolation Forest algorithm. It catches unseen/zero-day
attack patterns that the supervised MLP classifiers might miss.

Pipeline position:
    Dataset/Packet → MLP → **Anomaly Detector** → AttackLog → SHAP → QIGA → Response

Training:
    Trained on "Normal" traffic samples from existing datasets at startup.
    Anomalous patterns that deviate from normal behavior are flagged.

Scoring:
    -1 = Anomaly (suspicious deviation from normal)
    +1 = Normal (within learned distribution)
    anomaly_score = decision_function output (more negative = more anomalous)
"""

import os
import threading

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


class AnomalyDetector:
    """
    Isolation Forest based anomaly detection for healthcare network traffic.

    Supports multiple dataset schemas:
        - TON_IoT (network features)
        - PhiUSIIL (phishing URL features)
        - CERT (insider threat features)
    """

    # Feature schemas per dataset
    TON_FEATURES = [
        "src_bytes", "dst_bytes", "duration", "dst_port",
        "src_pkts", "dst_pkts", "conn_state_num",
    ]

    PHI_FEATURES = [
        "URLLength", "DomainLength", "IsDomainIP",
        "URLSimilarityIndex", "CharContinuationRate",
        "TLDLegitimateProb", "URLCharProb",
        "LetterRatioInURL", "NoOfSubDomain",
    ]

    CERT_FEATURES = [
        "hour", "logon_count", "device_count",
        "http_count", "email_count", "file_count",
    ]

    def __init__(self):
        self.models = {}        # dataset_source -> IsolationForest
        self.scalers = {}       # dataset_source -> StandardScaler
        self.is_trained = {}    # dataset_source -> bool
        self._lock = threading.Lock()

        self.feature_map = {
            "TON_IoT": self.TON_FEATURES,
            "PhiUSIIL": self.PHI_FEATURES,
            "CERT": self.CERT_FEATURES,
        }

    # ─────────────────────────────────────────────────────────────────────────
    # TRAINING
    # ─────────────────────────────────────────────────────────────────────────

    def train_from_csv(self, csv_path: str, max_samples: int = 5000):
        """
        Train Isolation Forest models from the unified dataset CSV.

        Extracts "Normal" traffic rows and trains a separate model
        for each dataset source (TON_IoT, PhiUSIIL, CERT).
        """
        if not os.path.exists(csv_path):
            print(f"[ANOMALY] Dataset not found: {csv_path}")
            return

        print("[ANOMALY] Loading training data...")

        try:
            df = pd.read_csv(csv_path, nrows=50000)
        except Exception as e:
            print(f"[ANOMALY] Failed to load CSV: {e}")
            return

        # Identify the label column
        label_col = None
        for candidate in ["label", "type", "attack_type", "Label", "Type"]:
            if candidate in df.columns:
                label_col = candidate
                break

        if label_col is None:
            print("[ANOMALY] No label column found in dataset. Skipping training.")
            return

        # Identify dataset column
        dataset_col = None
        for candidate in ["dataset", "Dataset", "source", "dataset_source"]:
            if candidate in df.columns:
                dataset_col = candidate
                break

        # Train per-dataset models
        for dataset_name, feature_list in self.feature_map.items():
            try:
                if dataset_col:
                    subset = df[df[dataset_col] == dataset_name]
                else:
                    # Try all columns, use what's available
                    subset = df

                # Filter normal traffic only for training
                normal_mask = subset[label_col].astype(str).str.lower().isin(
                    ["normal", "benign", "0", "legitimate"]
                )
                normal_data = subset[normal_mask]

                if len(normal_data) < 50:
                    print(
                        f"[ANOMALY] Insufficient normal samples for {dataset_name}: "
                        f"{len(normal_data)}. Skipping."
                    )
                    continue

                # Extract available features
                available_features = [
                    f for f in feature_list if f in normal_data.columns
                ]

                if len(available_features) < 2:
                    print(
                        f"[ANOMALY] Not enough features for {dataset_name}. "
                        f"Available: {available_features}. Skipping."
                    )
                    continue

                # Sample and prepare data
                sample = normal_data[available_features].head(max_samples).copy()
                sample = sample.apply(pd.to_numeric, errors="coerce").fillna(0)

                X = sample.values.astype(np.float64)

                # Scale features
                scaler = StandardScaler()
                X_scaled = scaler.fit_transform(X)

                # Train Isolation Forest
                model = IsolationForest(
                    n_estimators=100,
                    contamination=0.05,
                    max_samples="auto",
                    random_state=42,
                    n_jobs=-1,
                )
                model.fit(X_scaled)

                with self._lock:
                    self.models[dataset_name] = model
                    self.scalers[dataset_name] = scaler
                    self.is_trained[dataset_name] = True
                    # Store which features were actually used
                    self.feature_map[dataset_name] = available_features

                print(
                    f"[ANOMALY] Trained Isolation Forest for {dataset_name} "
                    f"on {len(X)} samples with {len(available_features)} features"
                )

            except Exception as e:
                print(f"[ANOMALY] Training failed for {dataset_name}: {e}")

        trained_count = sum(1 for v in self.is_trained.values() if v)
        print(f"[ANOMALY] Training complete. {trained_count}/3 models ready.")

    # ─────────────────────────────────────────────────────────────────────────
    # DETECTION
    # ─────────────────────────────────────────────────────────────────────────

    def detect_anomaly(
        self,
        raw_features: dict,
        dataset_source: str,
    ) -> dict:
        """
        Score a single event using the trained Isolation Forest.

        Returns:
            {
                "is_anomaly": bool,
                "anomaly_score": float,     # More negative = more anomalous
                "detector_type": "IsolationForest",
                "dataset_source": str,
                "features_used": list,
            }
        """
        default_result = {
            "is_anomaly": False,
            "anomaly_score": 0.0,
            "detector_type": "IsolationForest",
            "dataset_source": dataset_source,
            "features_used": [],
        }

        if not raw_features:
            return default_result

        with self._lock:
            model = self.models.get(dataset_source)
            scaler = self.scalers.get(dataset_source)
            feature_list = self.feature_map.get(dataset_source, [])

        if model is None or scaler is None:
            return default_result

        try:
            # Extract features from raw event
            feature_values = []
            for f in feature_list:
                val = raw_features.get(f, 0)
                try:
                    val = float(val)
                except (ValueError, TypeError):
                    val = 0.0
                feature_values.append(val)

            X = np.array([feature_values], dtype=np.float64)
            X_scaled = scaler.transform(X)

            # Predict: -1 = anomaly, 1 = normal
            prediction = model.predict(X_scaled)[0]

            # Decision function: more negative = more anomalous
            anomaly_score = float(model.decision_function(X_scaled)[0])

            return {
                "is_anomaly": prediction == -1,
                "anomaly_score": round(anomaly_score, 4),
                "detector_type": "IsolationForest",
                "dataset_source": dataset_source,
                "features_used": feature_list,
            }

        except Exception as e:
            print(f"[ANOMALY] Detection error for {dataset_source}: {e}")
            return default_result

    # ─────────────────────────────────────────────────────────────────────────
    # STATUS
    # ─────────────────────────────────────────────────────────────────────────

    def get_status(self) -> dict:
        """Return training status for all models."""
        with self._lock:
            return {
                "models_trained": dict(self.is_trained),
                "total_trained": sum(1 for v in self.is_trained.values() if v),
                "total_expected": len(self.feature_map),
            }


# ─────────────────────────────────────────────────────────────────────────────
# SINGLETON
# ─────────────────────────────────────────────────────────────────────────────

anomaly_detector = AnomalyDetector()
