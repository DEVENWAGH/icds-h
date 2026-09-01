"""
ICDS-H Inference Engine
========================

Pure inference engine for MLP predictions. No dataset replay.
No unified_dataset.csv dependency.

Responsibility:
    1. Accept raw features from any source (simulator, API, live capture, CSV).
    2. Build the exact model features.
    3. Run the trained MLP model.
    4. Return prediction, probability, risk score, severity, MITRE mapping.

This module DOES NOT generate response recommendations (QIGA does that).
"""

import os
import json
from datetime import datetime

import joblib
import numpy as np
import pandas as pd


class InferenceEngine:
    """
    MLP inference engine for TON_IoT (10 classes), PhiUSIIL, and CERT.

    No unified_dataset.csv. No replay indices. No class cycling.
    Just raw features in → MLP prediction out.
    """

    def __init__(self):
        base_dir = os.path.dirname(__file__)
        self.base_dir = base_dir

        def safe_load(path, name):
            if not os.path.exists(path):
                raise FileNotFoundError(
                    f"Missing required model artifact: {name} at {path}"
                )
            return joblib.load(path)

        # ── TON_IoT MLP ──────────────────────────────────────────────────────
        self.ton_model = safe_load(
            os.path.join(base_dir, "ton_iot_model.pkl"),
            "TON_IoT MLP Model",
        )
        self.ton_scaler = safe_load(
            os.path.join(base_dir, "ton_iot_scaler.pkl"),
            "TON_IoT Scaler",
        )
        self.ton_le = safe_load(
            os.path.join(base_dir, "ton_iot_le.pkl"),
            "TON_IoT Label Encoder",
        )

        # ── PhiUSIIL MLP ─────────────────────────────────────────────────────
        self.phi_model = safe_load(
            os.path.join(base_dir, "phishing_model.pkl"),
            "PhiUSIIL MLP Model",
        )
        self.phi_scaler = safe_load(
            os.path.join(base_dir, "phishing_scaler.pkl"),
            "PhiUSIIL Scaler",
        )

        # ── CERT MLP ─────────────────────────────────────────────────────────
        self.cert_model = safe_load(
            os.path.join(base_dir, "cert_model.pkl"),
            "CERT MLP Model",
        )
        self.cert_scaler = safe_load(
            os.path.join(base_dir, "cert_scaler.pkl"),
            "CERT Scaler",
        )

        # CERT encoders (try both naming conventions)
        cert_user_path = os.path.join(base_dir, "cert_user_le.pkl")
        cert_user_alt = os.path.join(base_dir, "cert_pc.pkl")
        self.cert_user_le = safe_load(cert_user_path, "CERT User Encoder")

        cert_pc_path = os.path.join(base_dir, "cert_pc_le.pkl")
        self.cert_pc_le = safe_load(cert_pc_path, "CERT PC Encoder")

        print("[ENGINE] Inference engine initialized (no unified_dataset.csv required)")

    # =========================================================================
    # HELPERS
    # =========================================================================

    @staticmethod
    def _safe_number(value, default=0.0):
        if value is None:
            return default
        try:
            if pd.isna(value):
                return default
        except Exception:
            pass
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _normalize_attack_label(label):
        """
        Convert model labels to canonical application labels.
        Supports all 10 TON_IoT classes + PhiUSIIL + CERT.
        """
        value = str(label).strip().lower()

        mapping = {
            "ddos": "DDoS",
            "dos": "DoS",
            "ransomware": "Ransomware",
            "backdoor": "Backdoor",
            "injection": "Injection",
            "password": "Password Attack",
            "scanning": "Scanning",
            "xss": "XSS",
            "mitm": "MITM",
            "phishing": "Phishing",
            "insider threat": "Insider Threat",
            "insider_threat": "Insider Threat",
            "insider": "Insider Threat",
            "normal": "Normal",
            "benign": "Normal",
            "legitimate": "Normal",
        }

        return mapping.get(value, "Normal")

    @staticmethod
    def _risk_from_prediction(label, confidence):
        """
        Deterministic risk score from MLP classification confidence.
        """
        confidence = float(confidence)

        weights = {
            "Normal": 0.05,
            "DDoS": 0.85,
            "DoS": 0.80,
            "Ransomware": 0.95,
            "Backdoor": 0.90,
            "Injection": 0.88,
            "Password Attack": 0.75,
            "Scanning": 0.40,
            "XSS": 0.82,
            "MITM": 0.92,
            "Phishing": 0.70,
            "Insider Threat": 0.80,
            "Anomaly (Zero-Day)": 0.85,
        }

        weight = weights.get(label, 0.50)
        score = confidence * weight

        return min(99.0, max(0.0, score))

    @staticmethod
    def _severity_from_risk(label, risk_score):
        if label == "Normal":
            return "LOW"
        if risk_score >= 80:
            return "CRITICAL"
        if risk_score >= 60:
            return "HIGH"
        if risk_score >= 35:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _mitre_mapping(label):
        """
        Valid MITRE ATT&CK IDs for all supported attack classes.
        """
        mapping = {
            "DDoS": ("T1498", "Network Denial of Service"),
            "DoS": ("T1499", "Endpoint Denial of Service"),
            "Ransomware": ("T1486", "Data Encrypted for Impact"),
            "Backdoor": ("T1059", "Command and Scripting Interpreter"),
            "Injection": ("T1190", "Exploit Public-Facing Application"),
            "Password Attack": ("T1110", "Brute Force"),
            "Scanning": ("T1046", "Network Service Discovery"),
            "XSS": ("T1189", "Drive-by Compromise"),
            "MITM": ("T1557", "Adversary-in-the-Middle"),
            "Phishing": ("T1566", "Phishing"),
            "Insider Threat": ("T1078.002", "Domain Accounts Abuse"),
            "Anomaly (Zero-Day)": (None, "Unmapped / Unknown Behavior"),
            "Normal": (None, None),
        }
        return mapping.get(label, (None, None))

    # =========================================================================
    # TON_IoT INFERENCE (all 10 classes)
    # =========================================================================

    def predict_ton_iot(self, raw_features):
        """
        Run TON_IoT MLP inference on raw network features.

        Args:
            raw_features: dict with src_port, dst_port, proto, duration,
                          src_bytes, dst_bytes, src_pkts, dst_pkts

        Returns:
            dict with prediction_label, confidence, risk_score, severity, etc.
        """
        proto_map = {"tcp": 6, "udp": 17, "icmp": 1}
        proto_value = str(raw_features.get("proto", "")).strip().lower()
        proto_num = proto_map.get(proto_value, 0)

        features = [
            self._safe_number(raw_features.get("src_port", 0)),
            self._safe_number(raw_features.get("dst_port", 0)),
            float(proto_num),
            self._safe_number(raw_features.get("duration", 0)),
            self._safe_number(raw_features.get("src_bytes", 0)),
            self._safe_number(raw_features.get("dst_bytes", 0)),
            self._safe_number(raw_features.get("src_pkts", 0)),
            self._safe_number(raw_features.get("dst_pkts", 0)),
        ]

        scaled = self.ton_scaler.transform([features])
        probabilities = self.ton_model.predict_proba(scaled)[0]

        predicted_index = int(np.argmax(probabilities))
        encoded_class = self.ton_model.classes_[predicted_index]
        raw_label = self.ton_le.inverse_transform([encoded_class])[0]
        label = self._normalize_attack_label(raw_label)
        confidence = float(np.max(probabilities) * 100.0)

        class_probs = {}
        for ci, prob in enumerate(probabilities):
            enc = self.ton_model.classes_[ci]
            dec = self.ton_le.inverse_transform([enc])[0]
            canonical = self._normalize_attack_label(dec)
            class_probs[canonical] = float(prob)

        n_features = int(getattr(self.ton_model, "n_features_in_", len(features)))
        n_classes = int(len(getattr(self.ton_model, "classes_", probabilities)))

        return self._format_event(
            dataset="TON_IoT",
            label=label,
            confidence=confidence,
            class_probs=class_probs,
            raw_features=raw_features,
            n_features=n_features,
            n_classes=n_classes,
            model_version="TON_IoT_MLP_v5",
        )

    # =========================================================================
    # PhiUSIIL INFERENCE
    # =========================================================================

    def predict_phishing(self, raw_features):
        """
        Run PhiUSIIL MLP inference on URL features.
        """
        columns = [
            "URLLength", "DomainLength", "URLSimilarityIndex",
            "CharContinuationRate", "TLDLegitimateProb", "NoOfSubDomain",
            "LetterRatioInURL", "DegitRatioInURL", "SpacialCharRatioInURL",
            "IsHTTPS",
        ]

        features = [
            self._safe_number(raw_features.get(col, 0))
            for col in columns
        ]

        scaled = self.phi_scaler.transform([features])
        probabilities = self.phi_model.predict_proba(scaled)[0]

        predicted_index = int(np.argmax(probabilities))
        predicted_class = self.phi_model.classes_[predicted_index]
        label = "Phishing" if int(predicted_class) == 1 else "Normal"
        confidence = float(np.max(probabilities) * 100.0)

        class_probs = {}
        for class_value, probability in zip(self.phi_model.classes_, probabilities):
            class_name = "Phishing" if int(class_value) == 1 else "Normal"
            class_probs[class_name] = float(probability)

        # Preserve URL/Domain in raw_features for display
        display_features = dict(raw_features)

        n_features = int(getattr(self.phi_model, "n_features_in_", len(features)))
        n_classes = int(len(getattr(self.phi_model, "classes_", probabilities)))

        return self._format_event(
            dataset="PhiUSIIL",
            label=label,
            confidence=confidence,
            class_probs=class_probs,
            raw_features=display_features,
            n_features=n_features,
            n_classes=n_classes,
            model_version="Phishing_MLP_v1",
        )

    # =========================================================================
    # CERT INFERENCE
    # =========================================================================

    def predict_cert(self, raw_features):
        """
        Run CERT MLP inference on insider-threat behavioral features.
        """
        # Extract time features
        try:
            parsed_datetime = pd.to_datetime(
                raw_features.get("date", "2010-01-01 00:00:00")
            )
            hour = int(parsed_datetime.hour)
            day_of_week = int(parsed_datetime.dayofweek)
        except Exception:
            hour = 0
            day_of_week = 0

        is_after_hours = 1 if (hour < 6 or hour > 19) else 0
        is_weekend = 1 if day_of_week >= 5 else 0

        activity_map = {"Logon": 0, "Logoff": 1, "Connect": 2, "Disconnect": 3}
        activity_value = str(raw_features.get("activity", ""))
        activity_type = activity_map.get(activity_value, 0)

        # Encode user and PC
        user_value = raw_features.get("user", "")
        try:
            user_encoded = int(self.cert_user_le.transform([user_value])[0])
        except Exception:
            user_encoded = 0

        pc_value = raw_features.get("pc", "")
        try:
            pc_encoded = int(self.cert_pc_le.transform([pc_value])[0])
        except Exception:
            pc_encoded = 0

        features = [
            hour, day_of_week, is_after_hours,
            is_weekend, activity_type, user_encoded, pc_encoded,
        ]

        scaled = self.cert_scaler.transform([features])
        probabilities = self.cert_model.predict_proba(scaled)[0]

        predicted_index = int(np.argmax(probabilities))
        predicted_class = self.cert_model.classes_[predicted_index]
        label = "Insider Threat" if int(predicted_class) == 1 else "Normal"
        confidence = float(np.max(probabilities) * 100.0)

        class_probs = {}
        for class_value, probability in zip(self.cert_model.classes_, probabilities):
            class_name = "Insider Threat" if int(class_value) == 1 else "Normal"
            class_probs[class_name] = float(probability)

        display_features = {
            "user": str(raw_features.get("user", "N/A")),
            "pc": str(raw_features.get("pc", "N/A")),
            "activity": str(raw_features.get("activity", "N/A")),
            "date": str(raw_features.get("date", "N/A")),
            "hour": float(hour),
            "dayofweek": float(day_of_week),
            "is_after_hours": float(is_after_hours),
            "is_weekend": float(is_weekend),
        }

        n_features = int(getattr(self.cert_model, "n_features_in_", len(features)))
        n_classes = int(len(getattr(self.cert_model, "classes_", probabilities)))

        return self._format_event(
            dataset="CERT",
            label=label,
            confidence=confidence,
            class_probs=class_probs,
            raw_features=display_features,
            n_features=n_features,
            n_classes=n_classes,
            model_version="CERT_MLP_v1",
        )

    # =========================================================================
    # UNIFIED PREDICT (routes by dataset_source)
    # =========================================================================

    def predict(self, raw_features, dataset_source):
        """
        Route inference to the correct model based on dataset_source.
        """
        if dataset_source == "TON_IoT":
            return self.predict_ton_iot(raw_features)
        elif dataset_source == "PhiUSIIL":
            return self.predict_phishing(raw_features)
        elif dataset_source == "CERT":
            return self.predict_cert(raw_features)
        else:
            raise ValueError(f"Unsupported dataset_source: {dataset_source}")

    # =========================================================================
    # FINAL EVENT FORMAT
    # =========================================================================

    def _format_event(
        self, dataset, label, confidence, class_probs,
        raw_features, n_features, n_classes, model_version,
    ):
        """
        Final result produced by the MLP inference stage.

        IMPORTANT:
        There is intentionally NO recommended_actions field here.
        Recommendations are generated later by QIGA.
        """
        risk_score = self._risk_from_prediction(label=label, confidence=confidence)
        severity = self._severity_from_risk(label=label, risk_score=risk_score)
        mitre_id, mitre_name = self._mitre_mapping(label)

        if label == "Normal":
            description = (
                f"[{dataset}] MLP classified the event as Normal "
                f"with {confidence:.1f}% confidence."
            )
        else:
            description = (
                f"[{dataset}] MLP detected {label} with "
                f"{confidence:.1f}% confidence and risk score "
                f"{risk_score:.1f}/100."
            )

        return {
            "dataset": dataset,
            "prediction_label": label,
            "confidence": float(confidence),
            "risk_score": float(risk_score),
            "severity": severity,
            "class_probs": class_probs,
            "raw_features": raw_features,
            "model_version": model_version,
            "n_features": int(n_features),
            "n_classes": int(n_classes),
            "class_names": list(class_probs.keys()),
            "mitre_technique_id": mitre_id,
            "mitre_technique_name": mitre_name,
            "description": description,
            "timestamp": datetime.utcnow().isoformat(),
        }

    # =========================================================================
    # SHAP HELPER
    # =========================================================================

    def explain_event(self, raw_features, dataset):
        from .shap_explainer import explainer
        return explainer.explain_shap(
            raw_features, dataset_source=dataset,
        )

    # =========================================================================
    # METRICS
    # =========================================================================

    def get_metrics(self, dataset):
        name_map = {
            "TON_IoT": "ton_iot",
            "PhiUSIIL": "phishing",
            "CERT": "cert",
        }
        filename = f"{name_map.get(dataset, 'ton_iot')}_metrics.json"
        path = os.path.join(self.base_dir, filename)

        try:
            with open(path, "r", encoding="utf-8") as file:
                return json.load(file)
        except Exception:
            return {}

    # =========================================================================
    # MODEL INFORMATION
    # =========================================================================

    def get_model_info(self, dataset):
        if dataset == "TON_IoT":
            classes = (
                list(self.ton_le.classes_)
                if hasattr(self.ton_le, "classes_")
                else ["normal"]
            )
            normalized = [self._normalize_attack_label(v) for v in classes]
            return {
                "n_features": int(getattr(self.ton_model, "n_features_in_", 8)),
                "n_classes": len(normalized),
                "class_names": normalized,
                "model_version": "TON_IoT_MLP_v5",
            }

        if dataset == "PhiUSIIL":
            model_classes = getattr(self.phi_model, "classes_", np.array([0, 1]))
            classes = [
                "Phishing" if int(v) == 1 else "Normal"
                for v in model_classes
            ]
            return {
                "n_features": int(getattr(self.phi_model, "n_features_in_", 10)),
                "n_classes": len(classes),
                "class_names": classes,
                "model_version": "Phishing_MLP_v1",
            }

        if dataset == "CERT":
            model_classes = getattr(self.cert_model, "classes_", np.array([0, 1]))
            classes = [
                "Insider Threat" if int(v) == 1 else "Normal"
                for v in model_classes
            ]
            return {
                "n_features": int(getattr(self.cert_model, "n_features_in_", 7)),
                "n_classes": len(classes),
                "class_names": classes,
                "model_version": "CERT_MLP_v1",
            }

        return {}

    # =========================================================================
    # LEGACY COMPATIBILITY: next_event() for old replay callers
    # =========================================================================

    def next_event(self):
        """
        Legacy compatibility. Generates a random event via the simulator
        and runs it through the real MLP.
        """
        from .event_simulator import simulator

        event_data = simulator.generate_random_event()
        return self.predict(
            event_data["raw_features"],
            event_data["dataset_source"],
        )


# =============================================================================
# SINGLETON
# =============================================================================

engine = InferenceEngine()
