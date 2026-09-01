"""
ICDS-H Anomaly Detector — Isolation Forest
=============================================

Loads pre-trained Isolation Forest models (one per dataset)
from saved artifacts in the cml/ directory.

No longer reads unified_dataset.csv at runtime.
"""

import os
import threading

import joblib
import numpy as np
import pandas as pd


# ─────────────────────────────────────────────────────────────────────────────
# FEATURE LISTS (must match what IF was trained on)
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_FEATURE_MAP = {
    "TON_IoT": [
        "src_port", "dst_port", "proto_num",
        "duration", "src_bytes", "dst_bytes",
        "src_pkts", "dst_pkts",
    ],
    "PhiUSIIL": [
        "URLLength", "DomainLength", "URLSimilarityIndex",
        "CharContinuationRate", "TLDLegitimateProb", "NoOfSubDomain",
        "LetterRatioInURL", "DegitRatioInURL", "SpacialCharRatioInURL",
        "IsHTTPS",
    ],
    "CERT": [
        "hour", "dayofweek", "is_after_hours",
        "is_weekend", "activity_type",
    ],
}

MODEL_DIR = os.path.dirname(__file__)


class AnomalyDetector:
    """
    Loads pre-trained Isolation Forest models from pkl artifacts
    and detects anomalies at inference time.
    """

    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.feature_map = dict(DEFAULT_FEATURE_MAP)
        self.is_trained = {
            "TON_IoT": False,
            "PhiUSIIL": False,
            "CERT": False,
        }
        self._lock = threading.Lock()

        # Attempt to load pre-trained models
        self._load_pretrained_models()

    # ─────────────────────────────────────────────────────────────────────────
    # LOAD PRE-TRAINED MODELS
    # ─────────────────────────────────────────────────────────────────────────

    def _load_pretrained_models(self):
        """Load pre-trained Isolation Forest model/scaler/feature artifacts."""

        artifact_map = {
            "TON_IoT": ("if_ton_model.pkl", "if_ton_scaler.pkl", "if_ton_features.pkl"),
            "PhiUSIIL": ("if_phi_model.pkl", "if_phi_scaler.pkl", "if_phi_features.pkl"),
            "CERT": ("if_cert_model.pkl", "if_cert_scaler.pkl", "if_cert_features.pkl"),
        }

        for dataset_name, (model_file, scaler_file, features_file) in artifact_map.items():
            model_path = os.path.join(MODEL_DIR, model_file)
            scaler_path = os.path.join(MODEL_DIR, scaler_file)
            features_path = os.path.join(MODEL_DIR, features_file)

            if (
                os.path.exists(model_path)
                and os.path.exists(scaler_path)
            ):
                try:
                    model = joblib.load(model_path)
                    scaler = joblib.load(scaler_path)

                    feature_list = DEFAULT_FEATURE_MAP.get(dataset_name, [])
                    if os.path.exists(features_path):
                        feature_list = joblib.load(features_path)

                    with self._lock:
                        self.models[dataset_name] = model
                        self.scalers[dataset_name] = scaler
                        self.feature_map[dataset_name] = feature_list
                        self.is_trained[dataset_name] = True

                    print(
                        f"[ANOMALY] Loaded pre-trained IF for {dataset_name} "
                        f"({len(feature_list)} features)"
                    )

                except Exception as e:
                    print(f"[ANOMALY] Failed to load {dataset_name} IF: {e}")
            else:
                print(
                    f"[ANOMALY] No pre-trained IF found for {dataset_name}. "
                    f"Run train_all.py to generate."
                )

    # ─────────────────────────────────────────────────────────────────────────
    # LEGACY: TRAIN FROM CSV (kept for backward compatibility)
    # ─────────────────────────────────────────────────────────────────────────

    def train_from_csv(self, csv_path: str, max_samples: int = 5000):
        """
        Legacy method: Train from a CSV file.
        Kept for backward compatibility but no longer the primary path.
        """
        from sklearn.preprocessing import StandardScaler
        from sklearn.ensemble import IsolationForest

        try:
            df = pd.read_csv(csv_path, low_memory=False)
        except Exception as e:
            print(f"[ANOMALY] CSV load failed: {e}")
            return

        label_col = None
        for candidate in ["type", "label", "Label", "class", "attack_type"]:
            if candidate in df.columns:
                label_col = candidate
                break

        if label_col is None:
            print("[ANOMALY] No label column found in dataset. Skipping training.")
            return

        dataset_col = None
        for candidate in ["dataset", "Dataset", "source", "dataset_source"]:
            if candidate in df.columns:
                dataset_col = candidate
                break

        for dataset_name, feature_list in self.feature_map.items():
            try:
                if dataset_col:
                    subset = df[df[dataset_col] == dataset_name]
                else:
                    subset = df

                normal_mask = subset[label_col].astype(str).str.lower().isin(
                    ["normal", "benign", "0", "legitimate"]
                )
                normal_data = subset[normal_mask]

                if len(normal_data) < 50:
                    continue

                available_features = [
                    f for f in feature_list if f in normal_data.columns
                ]

                if len(available_features) < 2:
                    continue

                sample = normal_data[available_features].head(max_samples).copy()
                sample = sample.apply(pd.to_numeric, errors="coerce").fillna(0)

                X = sample.values.astype(np.float64)

                scaler = StandardScaler()
                X_scaled = scaler.fit_transform(X)

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
                    self.feature_map[dataset_name] = available_features

                print(
                    f"[ANOMALY] Trained IF for {dataset_name} "
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
                "anomaly_risk": float,      # 0-99 deterministic risk score
                "detector_type": "IsolationForest",
                "dataset_source": str,
                "features_used": list,
            }
        """
        default_result = {
            "is_anomaly": False,
            "anomaly_score": 0.0,
            "anomaly_risk": 0.0,
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

            # Deterministic anomaly risk: normalized 0-99
            # IF decision_function returns negative for anomalies
            # Typical range is roughly -0.5 to 0.5
            # Map: score=-0.5 → risk=99, score=0.1 → risk=0
            anomaly_risk = min(99.0, max(0.0, (0.1 - anomaly_score) * 165.0))

            return {
                "is_anomaly": prediction == -1,
                "anomaly_score": round(anomaly_score, 4),
                "anomaly_risk": round(anomaly_risk, 1),
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
