import os
import json
from datetime import datetime

import joblib
import numpy as np
import pandas as pd


class DatasetReplayEngine:
    """
    Dataset replay + MLP inference engine.

    Responsibility of this module:
        1. Select a realistic row from the configured dataset replay.
        2. Build the exact model features.
        3. Run the trained MLP model.
        4. Return the MLP prediction, probability, risk score,
           severity, MITRE mapping and raw features.

    This module DOES NOT generate response recommendations.

    Recommendation flow:
        Dataset -> MLP -> AttackLog/RiskScore -> SHAP -> QIGA -> Recommendation
    """

    def __init__(self):
        # ---------------------------------------------------------------------
        # PATHS
        # ---------------------------------------------------------------------
        base_dir = os.path.dirname(__file__)
        dataset_dir = os.path.join(
            os.path.dirname(base_dir),
            "dataset",
        )

        self.base_dir = base_dir
        self.dataset_dir = dataset_dir

        # ---------------------------------------------------------------------
        # SAFE MODEL LOADER
        # ---------------------------------------------------------------------
        def safe_load(path, name):
            if not os.path.exists(path):
                raise FileNotFoundError(
                    f"Missing required model artifact: {name} at {path}"
                )

            return joblib.load(path)

        # ---------------------------------------------------------------------
        # TON_IoT MLP
        # ---------------------------------------------------------------------
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

        # ---------------------------------------------------------------------
        # PhiUSIIL / PHISHING MLP
        # ---------------------------------------------------------------------
        self.phi_model = safe_load(
            os.path.join(base_dir, "phishing_model.pkl"),
            "PhiUSIIL MLP Model",
        )

        self.phi_scaler = safe_load(
            os.path.join(base_dir, "phishing_scaler.pkl"),
            "PhiUSIIL Scaler",
        )

        # ---------------------------------------------------------------------
        # CERT MLP
        # ---------------------------------------------------------------------
        self.cert_model = safe_load(
            os.path.join(base_dir, "cert_model.pkl"),
            "CERT MLP Model",
        )

        self.cert_scaler = safe_load(
            os.path.join(base_dir, "cert_scaler.pkl"),
            "CERT Scaler",
        )

        self.cert_user_le = safe_load(
            os.path.join(base_dir, "cert_user_le.pkl"),
            "CERT User Encoder",
        )

        self.cert_pc_le = safe_load(
            os.path.join(base_dir, "cert_pc.pkl"),
            "CERT PC Encoder",
        ) if os.path.exists(
            os.path.join(base_dir, "cert_pc.pkl")
        ) else safe_load(
            os.path.join(base_dir, "cert_pc_le.pkl"),
            "CERT PC Encoder",
        )

        # ---------------------------------------------------------------------
        # DATASET
        # ---------------------------------------------------------------------
        dataset_path = os.path.join(
            dataset_dir,
            "unified_dataset.csv",
        )

        if not os.path.exists(dataset_path):
            raise FileNotFoundError(
                f"Missing unified dataset: {dataset_path}"
            )

        print("Loading unified dataset for replay...")

        unified_df = pd.read_csv(
            dataset_path,
            low_memory=False,
        )

        # ---------------------------------------------------------------------
        # SPLIT DATASETS
        # ---------------------------------------------------------------------
        self.ton_df = (
            unified_df[
                unified_df["dataset_source"] == "TON_IoT"
            ]
            .dropna(axis=1, how="all")
            .reset_index(drop=True)
        )

        self.phi_df = (
            unified_df[
                unified_df["dataset_source"] == "PhiUSIIL"
            ]
            .dropna(axis=1, how="all")
            .reset_index(drop=True)
        )

        self.cert_df = (
            unified_df[
                unified_df["dataset_source"] == "CERT"
            ]
            .dropna(axis=1, how="all")
            .reset_index(drop=True)
        )

        # ---------------------------------------------------------------------
        # CLASS SUBSETS
        #
        # IMPORTANT:
        # The source row is chosen from the dataset, but the final
        # classification is ALWAYS determined by the trained MLP.
        #
        # target_class only controls which realistic replay sample
        # is selected; it does NOT force the MLP output.
        # ---------------------------------------------------------------------
        self.ton_normal = self._class_subset(
            self.ton_df,
            "normal",
        )
        self.ton_ddos = self._class_subset(
            self.ton_df,
            "ddos",
        )
        self.ton_ransomware = self._class_subset(
            self.ton_df,
            "ransomware",
        )

        self.phi_normal = self._class_subset(
            self.phi_df,
            "normal",
        )
        self.phi_phishing = self._class_subset(
            self.phi_df,
            "phishing",
        )

        self.cert_normal = self._class_subset(
            self.cert_df,
            "normal",
        )
        self.cert_insider = self._class_subset(
            self.cert_df,
            "insider threat",
        )

        # ---------------------------------------------------------------------
        # REPLAY INDICES
        # ---------------------------------------------------------------------
        self.indices = {
            "ton_normal": 0,
            "ton_ddos": 0,
            "ton_ransomware": 0,
            "phi_normal": 0,
            "phi_phishing": 0,
            "cert_normal": 0,
            "cert_insider": 0,
        }

        # ---------------------------------------------------------------------
        # DATASET ROUND-ROBIN
        # ---------------------------------------------------------------------
        self.dataset_cycle = [
            "TON_IoT",
            "PhiUSIIL",
            "CERT",
        ]

        self.current_ds_idx = 0

        self.unseen_phishing_events = []
        self.unseen_phishing_index = 0

        # ---------------------------------------------------------------------
        # REPLAY CLASS ROTATION
        #
        # Again, this only chooses realistic source rows.
        # The MLP prediction remains authoritative.
        # ---------------------------------------------------------------------
        self.class_cycles = {
            "TON_IoT": [
                "normal",
                "ddos",
                "normal",
                "ransomware",
            ],
            "PhiUSIIL": [
                "normal",
                "phishing",
            ],
            "CERT": [
                "normal",
                "insider",
            ],
        }

        self.class_cycle_idx = {
            "TON_IoT": 0,
            "PhiUSIIL": 0,
            "CERT": 0,
        }

    # =========================================================================
    # HELPERS
    # =========================================================================

    @staticmethod
    def _class_subset(df, class_name):
        """
        Safely return rows belonging to a replay class.
        """
        if "type" not in df.columns:
            return pd.DataFrame()

        return (
            df[
                df["type"]
                .fillna("")
                .astype(str)
                .str.strip()
                .str.lower()
                == class_name.lower()
            ]
            .reset_index(drop=True)
        )

    @staticmethod
    def _safe_number(value, default=0.0):
        """
        Convert arbitrary dataset values to float safely.
        """
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
        Convert model labels to the application's canonical labels.
        """
        value = str(label).strip().lower()

        if value == "ddos":
            return "DDoS"

        if value == "ransomware":
            return "Ransomware"

        if value == "phishing":
            return "Phishing"

        if value in {
            "insider threat",
            "insider_threat",
            "insider",
        }:
            return "Insider Threat"

        return "Normal"

    @staticmethod
    def _risk_from_prediction(label, confidence):
        """
        Convert the MLP classification confidence into the application's
        risk score.
        """
        confidence = float(confidence)

        if label == "Normal":
            score = confidence * 0.05

        elif label == "DDoS":
            score = confidence * 0.85

        elif label == "Ransomware":
            score = confidence * 0.95

        elif label == "Phishing":
            score = confidence * 0.70

        elif label == "Insider Threat":
            score = confidence * 0.80

        else:
            score = 50.0

        return min(
            99.0,
            max(
                0.0,
                score,
            ),
        )

    @staticmethod
    def _severity_from_risk(label, risk_score):
        """
        Derive severity from the MLP-derived risk score.
        """
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
        MITRE ATT&CK mapping based on the final MLP classification.
        """
        mapping = {
            "DDoS": (
                "T1498",
                "Network Denial of Service",
            ),
            "Ransomware": (
                "T1486",
                "Data Encrypted for Impact",
            ),
            "Phishing": (
                "T1566",
                "Phishing",
            ),
            "Insider Threat": (
                "T1078.002",
                "Domain Accounts Abuse",
            ),
            "Normal": (
                None,
                None,
            ),
        }

        return mapping.get(
            label,
            (
                None,
                None,
            ),
        )

    # =========================================================================
    # MAIN REPLAY ENTRY
    # =========================================================================

    def next_event(self):
        """
        Select the next realistic dataset row and run the appropriate MLP.

        Final prediction is always produced by the trained MLP.
        """
        dataset = self.dataset_cycle[
            self.current_ds_idx
        ]

        self.current_ds_idx = (
            self.current_ds_idx + 1
        ) % len(self.dataset_cycle)

        cycle = self.class_cycles[dataset]

        cycle_index = self.class_cycle_idx[dataset]

        target_class = cycle[cycle_index]

        self.class_cycle_idx[dataset] = (
            cycle_index + 1
        ) % len(cycle)

        if dataset == "TON_IoT":
            return self._process_ton(
                target_class
            )

        if dataset == "PhiUSIIL":
            return self._process_phi(
                target_class
            )

        if dataset == "CERT":
            return self._process_cert(
                target_class
            )

        raise ValueError(
            f"Unsupported dataset: {dataset}"
        )
       
    def load_unseen_phishing_events(self, filename="realtime_test/unseen_phishing_test.csv"):
        
        test_path = os.path.join(self.dataset_dir, filename)

        if not os.path.exists(test_path):
            raise FileNotFoundError(
                f"Unseen phishing test file not found: {test_path}"
            )

        df = pd.read_csv(test_path, low_memory=False)

        required_columns = [
            "URL",
            "Domain",
            "URLLength",
            "DomainLength",
            "URLSimilarityIndex",
            "CharContinuationRate",
            "TLDLegitimateProb",
            "NoOfSubDomain",
            "LetterRatioInURL",
            "DegitRatioInURL",
            "SpacialCharRatioInURL",
            "IsHTTPS",
        ]

        missing = [
            col for col in required_columns
            if col not in df.columns
        ]

        if missing:
            raise ValueError(
                f"Missing required PhiUSIIL columns: {missing}"
            )

        events = []

        for _, row in df.iterrows():
            features = [
                self._safe_number(row.get("URLLength", 0)),
                self._safe_number(row.get("DomainLength", 0)),
                self._safe_number(row.get("URLSimilarityIndex", 0)),
                self._safe_number(row.get("CharContinuationRate", 0)),
                self._safe_number(row.get("TLDLegitimateProb", 0)),
                self._safe_number(row.get("NoOfSubDomain", 0)),
                self._safe_number(row.get("LetterRatioInURL", 0)),
                self._safe_number(row.get("DegitRatioInURL", 0)),
                self._safe_number(row.get("SpacialCharRatioInURL", 0)),
                self._safe_number(row.get("IsHTTPS", 0)),
            ]

            scaled = self.phi_scaler.transform([features])

            probabilities = self.phi_model.predict_proba(scaled)[0]

            predicted_index = int(np.argmax(probabilities))
            predicted_class = self.phi_model.classes_[predicted_index]

            label = (
                "Phishing"
                if int(predicted_class) == 1
                else "Normal"
            )

            confidence = float(
                np.max(probabilities) * 100.0
            )

            class_probs = {}

            for class_value, probability in zip(
                self.phi_model.classes_,
                probabilities,
            ):
                class_name = (
                    "Phishing"
                    if int(class_value) == 1
                    else "Normal"
                )

                class_probs[class_name] = float(probability)

            raw_features = {
                "URL": str(row.get("URL", "N/A")),
                "Domain": str(row.get("Domain", "N/A")),
                "URLLength": features[0],
                "DomainLength": features[1],
                "URLSimilarityIndex": features[2],
                "CharContinuationRate": features[3],
                "TLDLegitimateProb": features[4],
                "NoOfSubDomain": features[5],
                "LetterRatioInURL": features[6],
                "DegitRatioInURL": features[7],
                "SpacialCharRatioInURL": features[8],
                "IsHTTPS": features[9],
            }

            n_features = int(
                getattr(
                    self.phi_model,
                    "n_features_in_",
                    len(features),
                )
            )

            n_classes = int(
                len(
                    getattr(
                        self.phi_model,
                        "classes_",
                        probabilities,
                    )
                )
            )

            event = self._format_event(
                dataset="PhiUSIIL",
                label=label,
                confidence=confidence,
                class_probs=class_probs,
                raw_features=raw_features,
                n_features=n_features,
                n_classes=n_classes,
                model_version="Phishing_MLP_v1",
            )
            event["input_source"] = "UNSEEN_TEST"
            events.append(event)

        return events
    # =========================================================================
    # TON_IoT
    # =========================================================================

    def _process_ton(self, target_class):
        if target_class == "normal":
            df_target = self.ton_normal
            idx_key = "ton_normal"

        elif target_class == "ddos":
            df_target = self.ton_ddos
            idx_key = "ton_ddos"

        elif target_class == "ransomware":
            df_target = self.ton_ransomware
            idx_key = "ton_ransomware"

        else:
            raise ValueError(
                f"Unknown TON_IoT replay class: {target_class}"
            )

        if df_target.empty:
            counts = (
                self.ton_df["type"]
                .value_counts()
                .to_dict()
                if "type" in self.ton_df.columns
                else {}
            )

            raise ValueError(
                "TON_IoT dataset subset is empty. "
                f"Requested={target_class}; Available={counts}"
            )

        idx = self.indices[idx_key]

        row = df_target.iloc[idx]

        self.indices[idx_key] = (
            idx + 1
        ) % len(df_target)

        proto_map = {
            "tcp": 6,
            "udp": 17,
            "icmp": 1,
        }

        proto_value = str(
            row.get(
                "proto",
                "",
            )
        ).strip().lower()

        proto_num = proto_map.get(
            proto_value,
            0,
        )

        features = [
            self._safe_number(
                row.get(
                    "src_port",
                    0,
                )
            ),
            self._safe_number(
                row.get(
                    "dst_port",
                    0,
                )
            ),
            float(proto_num),
            self._safe_number(
                row.get(
                    "duration",
                    0,
                )
            ),
            self._safe_number(
                row.get(
                    "src_bytes",
                    0,
                )
            ),
            self._safe_number(
                row.get(
                    "dst_bytes",
                    0,
                )
            ),
            self._safe_number(
                row.get(
                    "src_pkts",
                    0,
                )
            ),
            self._safe_number(
                row.get(
                    "dst_pkts",
                    0,
                )
            ),
        ]

        scaled = self.ton_scaler.transform(
            [features]
        )

        probabilities = (
            self.ton_model
            .predict_proba(
                scaled
            )[0]
        )

        predicted_index = int(
            np.argmax(probabilities)
        )

        encoded_class = (
            self.ton_model.classes_[
                predicted_index
            ]
        )

        raw_label = (
            self.ton_le
            .inverse_transform(
                [encoded_class]
            )[0]
        )

        label = self._normalize_attack_label(
            raw_label
        )

        confidence = float(
            np.max(probabilities)
            * 100.0
        )

        class_probs = {}

        for class_index, probability in enumerate(
            probabilities
        ):
            encoded = (
                self.ton_model.classes_[
                    class_index
                ]
            )

            decoded = (
                self.ton_le
                .inverse_transform(
                    [encoded]
                )[0]
            )

            canonical = (
                self._normalize_attack_label(
                    decoded
                )
            )

            class_probs[canonical] = float(
                probability
            )

        raw_features = {
            "src_ip": str(
                row.get(
                    "src_ip",
                    "N/A",
                )
            ),
            "dst_ip": str(
                row.get(
                    "dst_ip",
                    "N/A",
                )
            ),
            "src_port": str(
                row.get(
                    "src_port",
                    "N/A",
                )
            ),
            "dst_port": str(
                row.get(
                    "dst_port",
                    "N/A",
                )
            ),
            "proto": str(
                row.get(
                    "proto",
                    "N/A",
                )
            ),
            "duration": float(
                features[3]
            ),
            "src_bytes": float(
                features[4]
            ),
            "dst_bytes": float(
                features[5]
            ),
            "src_pkts": float(
                features[6]
            ),
            "dst_pkts": float(
                features[7]
            ),
        }

        n_features = int(
            getattr(
                self.ton_model,
                "n_features_in_",
                len(features),
            )
        )

        n_classes = int(
            len(
                getattr(
                    self.ton_model,
                    "classes_",
                    probabilities,
                )
            )
        )

        return self._format_event(
            dataset="TON_IoT",
            label=label,
            confidence=confidence,
            class_probs=class_probs,
            raw_features=raw_features,
            n_features=n_features,
            n_classes=n_classes,
            model_version="TON_IoT_MLP_v1",
        )

    # =========================================================================
    # PhiUSIIL
    # =========================================================================

    def _process_phi(self, target_class):
        if target_class == "normal":
            df_target = self.phi_normal
            idx_key = "phi_normal"

        elif target_class == "phishing":
            df_target = self.phi_phishing
            idx_key = "phi_phishing"

        else:
            raise ValueError(
                f"Unknown PhiUSIIL replay class: {target_class}"
            )

        if df_target.empty:
            counts = (
                self.phi_df["type"]
                .value_counts()
                .to_dict()
                if "type" in self.phi_df.columns
                else {}
            )

            raise ValueError(
                "PhiUSIIL dataset subset is empty. "
                f"Requested={target_class}; Available={counts}"
            )

        idx = self.indices[idx_key]

        row = df_target.iloc[idx]

        self.indices[idx_key] = (
            idx + 1
        ) % len(df_target)

        columns = [
            "URLLength",
            "DomainLength",
            "URLSimilarityIndex",
            "CharContinuationRate",
            "TLDLegitimateProb",
            "NoOfSubDomain",
            "LetterRatioInURL",
            "DegitRatioInURL",
            "SpacialCharRatioInURL",
            "IsHTTPS",
        ]

        features = [
            self._safe_number(
                row.get(
                    column,
                    0,
                )
            )
            for column in columns
        ]

        scaled = self.phi_scaler.transform(
            [features]
        )

        probabilities = (
            self.phi_model
            .predict_proba(
                scaled
            )[0]
        )

        predicted_index = int(
            np.argmax(probabilities)
        )

        predicted_class = (
            self.phi_model.classes_[
                predicted_index
            ]
        )

        label = (
            "Phishing"
            if int(predicted_class) == 1
            else "Normal"
        )

        confidence = float(
            np.max(probabilities)
            * 100.0
        )

        class_probs = {}

        for class_value, probability in zip(
            self.phi_model.classes_,
            probabilities,
        ):
            class_name = (
                "Phishing"
                if int(class_value) == 1
                else "Normal"
            )

            class_probs[class_name] = float(
                probability
            )

        raw_features = {
            "URL": str(
                row.get(
                    "URL",
                    "N/A",
                )
            ),
            "Domain": str(
                row.get(
                    "Domain",
                    "N/A",
                )
            ),
        }

        for index, column in enumerate(columns):
            raw_features[column] = float(
                features[index]
            )

        n_features = int(
            getattr(
                self.phi_model,
                "n_features_in_",
                len(features),
            )
        )

        n_classes = int(
            len(
                getattr(
                    self.phi_model,
                    "classes_",
                    probabilities,
                )
            )
        )

        return self._format_event(
            dataset="PhiUSIIL",
            label=label,
            confidence=confidence,
            class_probs=class_probs,
            raw_features=raw_features,
            n_features=n_features,
            n_classes=n_classes,
            model_version="Phishing_MLP_v1",
        )

    # =========================================================================
    # CERT
    # =========================================================================

    def _process_cert(self, target_class):
        if target_class == "normal":
            df_target = self.cert_normal
            idx_key = "cert_normal"

        elif target_class == "insider":
            df_target = self.cert_insider
            idx_key = "cert_insider"

        else:
            raise ValueError(
                f"Unknown CERT replay class: {target_class}"
            )

        if df_target.empty:
            counts = (
                self.cert_df["type"]
                .value_counts()
                .to_dict()
                if "type" in self.cert_df.columns
                else {}
            )

            raise ValueError(
                "CERT dataset subset is empty. "
                f"Requested={target_class}; Available={counts}"
            )

        idx = self.indices[idx_key]

        row = df_target.iloc[idx]

        self.indices[idx_key] = (
            idx + 1
        ) % len(df_target)

        # ---------------------------------------------------------------------
        # Date -> time features
        # ---------------------------------------------------------------------
        try:
            parsed_datetime = pd.to_datetime(
                row.get(
                    "date",
                    "2010-01-01 00:00:00",
                )
            )

            hour = int(
                parsed_datetime.hour
            )

            day_of_week = int(
                parsed_datetime.dayofweek
            )

        except Exception:
            hour = 0
            day_of_week = 0

        is_after_hours = (
            1
            if (
                hour < 6
                or hour > 19
            )
            else 0
        )

        is_weekend = (
            1
            if day_of_week >= 5
            else 0
        )

        activity_map = {
            "Logon": 0,
            "Logoff": 1,
            "Connect": 2,
            "Disconnect": 3,
        }

        activity_value = str(
            row.get(
                "activity",
                "",
            )
        )

        activity_type = activity_map.get(
            activity_value,
            0,
        )

        # ---------------------------------------------------------------------
        # Encoded user
        # ---------------------------------------------------------------------
        user_value = row.get(
            "user",
            "",
        )

        try:
            user_encoded = int(
                self.cert_user_le
                .transform(
                    [user_value]
                )[0]
            )
        except Exception:
            user_encoded = 0

        # ---------------------------------------------------------------------
        # Encoded PC
        # ---------------------------------------------------------------------
        pc_value = row.get(
            "pc",
            "",
        )

        try:
            pc_encoded = int(
                self.cert_pc_le
                .transform(
                    [pc_value]
                )[0]
            )
        except Exception:
            pc_encoded = 0

        features = [
            hour,
            day_of_week,
            is_after_hours,
            is_weekend,
            activity_type,
            user_encoded,
            pc_encoded,
        ]

        scaled = self.cert_scaler.transform(
            [features]
        )

        probabilities = (
            self.cert_model
            .predict_proba(
                scaled
            )[0]
        )

        predicted_index = int(
            np.argmax(probabilities)
        )

        predicted_class = (
            self.cert_model.classes_[
                predicted_index
            ]
        )

        label = (
            "Insider Threat"
            if int(predicted_class) == 1
            else "Normal"
        )

        confidence = float(
            np.max(probabilities)
            * 100.0
        )

        class_probs = {}

        for class_value, probability in zip(
            self.cert_model.classes_,
            probabilities,
        ):
            class_name = (
                "Insider Threat"
                if int(class_value) == 1
                else "Normal"
            )

            class_probs[class_name] = float(
                probability
            )

        raw_features = {
            "user": str(
                row.get(
                    "user",
                    "N/A",
                )
            ),
            "pc": str(
                row.get(
                    "pc",
                    "N/A",
                )
            ),
            "activity": str(
                row.get(
                    "activity",
                    "N/A",
                )
            ),
            "date": str(
                row.get(
                    "date",
                    "N/A",
                )
            ),
            "hour": float(
                hour
            ),
            "dayofweek": float(
                day_of_week
            ),
            "is_after_hours": float(
                is_after_hours
            ),
            "is_weekend": float(
                is_weekend
            ),
        }

        n_features = int(
            getattr(
                self.cert_model,
                "n_features_in_",
                len(features),
            )
        )

        n_classes = int(
            len(
                getattr(
                    self.cert_model,
                    "classes_",
                    probabilities,
                )
            )
        )

        return self._format_event(
            dataset="CERT",
            label=label,
            confidence=confidence,
            class_probs=class_probs,
            raw_features=raw_features,
            n_features=n_features,
            n_classes=n_classes,
            model_version="CERT_MLP_v1",
        )

    # =========================================================================
    # FINAL EVENT FORMAT
    # =========================================================================

    def _format_event(
        self,
        dataset,
        label,
        confidence,
        class_probs,
        raw_features,
        n_features,
        n_classes,
        model_version,
    ):
        """
        Final result produced by the MLP inference stage.

        IMPORTANT:
        There is intentionally NO recommended_actions field here.
        Recommendations are generated later by QIGA.
        """

        risk_score = self._risk_from_prediction(
            label=label,
            confidence=confidence,
        )

        severity = self._severity_from_risk(
            label=label,
            risk_score=risk_score,
        )

        mitre_id, mitre_name = (
            self._mitre_mapping(
                label
            )
        )

        if label == "Normal":
            description = (
                f"[{dataset}] MLP classified the "
                f"event as Normal with "
                f"{confidence:.1f}% confidence."
            )
        else:
            description = (
                f"[{dataset}] MLP detected "
                f"{label} with "
                f"{confidence:.1f}% confidence "
                f"and risk score "
                f"{risk_score:.1f}/100."
            )

        return {
            "dataset": dataset,

            # -----------------------------------------------------------------
            # MLP RESULT
            # -----------------------------------------------------------------
            "prediction_label": label,
            "confidence": float(confidence),
            "risk_score": float(risk_score),
            "severity": severity,
            "class_probs": class_probs,

            # -----------------------------------------------------------------
            # MODEL / INPUT INFORMATION
            # -----------------------------------------------------------------
            "raw_features": raw_features,
            "model_version": model_version,
            "n_features": int(n_features),
            "n_classes": int(n_classes),
            "class_names": list(
                class_probs.keys()
            ),

            # -----------------------------------------------------------------
            # SECURITY CONTEXT
            # -----------------------------------------------------------------
            "mitre_technique_id": mitre_id,
            "mitre_technique_name": mitre_name,

            # -----------------------------------------------------------------
            # IMPORTANT:
            # No response recommendation is generated here.
            # QIGA performs that stage in main.py.
            # -----------------------------------------------------------------
            "description": description,

            "timestamp": (
                datetime.utcnow()
                .isoformat()
            ),
        }

    # =========================================================================
    # SHAP HELPER
    # =========================================================================

    def explain_event(
        self,
        raw_features,
        dataset,
    ):
        """
        Convenience wrapper for the SHAP explainer.

        SHAP is executed only after MLP inference has produced
        the event's raw_features and dataset.
        """
        from .shap_explainer import explainer

        return explainer.explain_shap(
            raw_features,
            dataset_source=dataset,
        )

    # =========================================================================
    # METRICS
    # =========================================================================

    def get_metrics(
        self,
        dataset,
    ):
        name_map = {
            "TON_IoT": "ton_iot",
            "PhiUSIIL": "phishing",
            "CERT": "cert",
        }

        filename = (
            f"{name_map.get(dataset, 'ton_iot')}"
            "_metrics.json"
        )

        path = os.path.join(
            self.base_dir,
            filename,
        )

        try:
            with open(
                path,
                "r",
                encoding="utf-8",
            ) as file:
                return json.load(file)

        except Exception:
            return {}

    # =========================================================================
    # MODEL INFORMATION
    # =========================================================================

    def get_model_info(
        self,
        dataset,
    ):
        if dataset == "TON_IoT":

            classes = (
                list(
                    self.ton_le.classes_
                )
                if hasattr(
                    self.ton_le,
                    "classes_",
                )
                else [
                    "normal",
                    "ddos",
                    "ransomware",
                ]
            )

            normalized_classes = [
                self._normalize_attack_label(
                    value
                )
                for value in classes
            ]

            return {
                "n_features": int(
                    getattr(
                        self.ton_model,
                        "n_features_in_",
                        8,
                    )
                ),
                "n_classes": len(
                    normalized_classes
                ),
                "class_names": normalized_classes,
                "model_version": "TON_IoT_MLP_v1",
            }

        if dataset == "PhiUSIIL":

            model_classes = getattr(
                self.phi_model,
                "classes_",
                np.array([0, 1]),
            )

            classes = [
                (
                    "Phishing"
                    if int(value) == 1
                    else "Normal"
                )
                for value in model_classes
            ]

            return {
                "n_features": int(
                    getattr(
                        self.phi_model,
                        "n_features_in_",
                        10,
                    )
                ),
                "n_classes": len(classes),
                "class_names": classes,
                "model_version": "Phishing_MLP_v1",
            }

        if dataset == "CERT":

            model_classes = getattr(
                self.cert_model,
                "classes_",
                np.array([0, 1]),
            )

            classes = [
                (
                    "Insider Threat"
                    if int(value) == 1
                    else "Normal"
                )
                for value in model_classes
            ]

            return {
                "n_features": int(
                    getattr(
                        self.cert_model,
                        "n_features_in_",
                        7,
                    )
                ),
                "n_classes": len(classes),
                "class_names": classes,
                "model_version": "CERT_MLP_v1",
            }

        return {}


# =============================================================================
# SINGLETON
# =============================================================================

engine = DatasetReplayEngine()
