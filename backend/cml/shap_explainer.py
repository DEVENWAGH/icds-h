import os
import csv
from typing import Dict, List, Optional, Tuple

import pandas as pd
import joblib
import numpy as np
import shap


# =============================================================================
# MODEL DIRECTORY
# =============================================================================

MODEL_DIR = os.path.dirname(__file__)


# =============================================================================
# FEATURE DEFINITIONS
# =============================================================================

# -----------------------------------------------------------------------------
# TON_IoT
# -----------------------------------------------------------------------------

TON_FEATURE_NAMES = [
    "src_port",
    "dst_port",
    "proto_num",
    "duration",
    "src_bytes",
    "dst_bytes",
    "src_pkts",
    "dst_pkts",
]

TON_FEATURE_LABELS = {
    "src_port": "Source Port",
    "dst_port": "Destination Port",
    "proto_num": "Protocol",
    "duration": "Flow Duration",
    "src_bytes": "Source Bytes",
    "dst_bytes": "Destination Bytes",
    "src_pkts": "Source Packets",
    "dst_pkts": "Destination Packets",
}


# -----------------------------------------------------------------------------
# PhiUSIIL
# -----------------------------------------------------------------------------

PHI_FEATURE_NAMES = [
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

PHI_FEATURE_LABELS = {
    "URLLength": "URL Length",
    "DomainLength": "Domain Length",
    "URLSimilarityIndex": "URL Similarity Index",
    "CharContinuationRate": "Character Continuation Rate",
    "TLDLegitimateProb": "TLD Legitimacy Probability",
    "NoOfSubDomain": "Number of Subdomains",
    "LetterRatioInURL": "Letter Ratio in URL",
    "DegitRatioInURL": "Digit Ratio in URL",
    "SpacialCharRatioInURL": "Special Character Ratio in URL",
    "IsHTTPS": "Uses HTTPS",
}


# -----------------------------------------------------------------------------
# CERT
# -----------------------------------------------------------------------------

CERT_FEATURE_NAMES = [
    "hour",
    "dayofweek",
    "is_after_hours",
    "is_weekend",
    "activity_type",
    "user_enc",
    "pc_enc",
]

CERT_FEATURE_LABELS = {
    "hour": "Hour of Day",
    "dayofweek": "Day of Week",
    "is_after_hours": "After-Hours Access",
    "is_weekend": "Weekend Access",
    "activity_type": "Activity Type",
    "user_enc": "User Identity",
    "pc_enc": "Workstation Identity",
}


# =============================================================================
# EXPLAINER
# =============================================================================

class ICDSExplainer:
    """
    Dataset-aware SHAP explainer for the ICDS-H MLP models.

    Supported datasets:
        TON_IoT
        PhiUSIIL
        CERT

    Important architecture rule:

        MLP = prediction authority
        SHAP = explanation only

    SHAP never changes the MLP prediction.
    """

    SUPPORTED_DATASETS = {
        "TON_IoT",
        "PhiUSIIL",
        "CERT",
    }

    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.encoders = {}

        # One SHAP explainer per dataset.
        self.explainers = {}

        self._load_models()

    # =========================================================================
    # MODEL LOADING
    # =========================================================================

    def _safe_load(self, path: str, name: str):
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"[XAI] Missing {name}: {path}"
            )

        return joblib.load(path)

    def _load_models(self):
        # ---------------------------------------------------------------------
        # TON_IoT
        # ---------------------------------------------------------------------

        ton_model_path = os.path.join(
            MODEL_DIR,
            "ton_iot_model.pkl",
        )

        if os.path.exists(ton_model_path):
            self.models["TON_IoT"] = self._safe_load(
                ton_model_path,
                "TON_IoT model",
            )

            self.scalers["TON_IoT"] = self._safe_load(
                os.path.join(
                    MODEL_DIR,
                    "ton_iot_scaler.pkl",
                ),
                "TON_IoT scaler",
            )

            self.encoders["TON_IoT"] = self._safe_load(
                os.path.join(
                    MODEL_DIR,
                    "ton_iot_le.pkl",
                ),
                "TON_IoT label encoder",
            )

            print("[XAI] TON_IoT MLP loaded.")
        else:
            print("[XAI] Warning: TON_IoT model not found.")

        # ---------------------------------------------------------------------
        # PhiUSIIL
        # ---------------------------------------------------------------------

        phi_model_path = os.path.join(
            MODEL_DIR,
            "phishing_model.pkl",
        )

        if os.path.exists(phi_model_path):
            self.models["PhiUSIIL"] = self._safe_load(
                phi_model_path,
                "PhiUSIIL model",
            )

            self.scalers["PhiUSIIL"] = self._safe_load(
                os.path.join(
                    MODEL_DIR,
                    "phishing_scaler.pkl",
                ),
                "PhiUSIIL scaler",
            )

            print("[XAI] PhiUSIIL MLP loaded.")
        else:
            print("[XAI] Warning: PhiUSIIL model not found.")

        # ---------------------------------------------------------------------
        # CERT
        # ---------------------------------------------------------------------

        cert_model_path = os.path.join(
            MODEL_DIR,
            "cert_model.pkl",
        )

        if os.path.exists(cert_model_path):
            self.models["CERT"] = self._safe_load(
                cert_model_path,
                "CERT model",
            )

            self.scalers["CERT"] = self._safe_load(
                os.path.join(
                    MODEL_DIR,
                    "cert_scaler.pkl",
                ),
                "CERT scaler",
            )

            self.encoders["cert_user_le"] = self._safe_load(
                os.path.join(
                    MODEL_DIR,
                    "cert_user_le.pkl",
                ),
                "CERT user encoder",
            )

            self.encoders["cert_pc_le"] = self._safe_load(
                os.path.join(
                    MODEL_DIR,
                    "cert_pc_le.pkl",
                ),
                "CERT PC encoder",
            )

            print("[XAI] CERT MLP loaded.")
        else:
            print("[XAI] Warning: CERT model not found.")

    # =========================================================================
    # PUBLIC SHAP API
    # =========================================================================

    def explain_shap(
        self,
        raw_features: Dict,
        dataset_source: Optional[str] = None,
        top_k: int = 5,
        expected_prediction_label: Optional[str] = None,
    ) -> Dict:
        """
        Explain the SAME persisted AttackLog event that was classified by MLP.

        expected_prediction_label:
            The label already produced by the backend MLP pipeline.

        SHAP replays the same preprocessing/model only to verify that the
        explanation corresponds to the same prediction.
        """

        if not isinstance(raw_features, dict):
            raise ValueError(
                "raw_features must be a dictionary"
            )

        if not dataset_source:
            raise ValueError(
                "dataset_source is required for XAI explanation"
            )

        if dataset_source not in self.SUPPORTED_DATASETS:
            raise ValueError(
                f"Unknown dataset_source: {dataset_source}"
            )

        if dataset_source not in self.models:
            raise ValueError(
                f"Model for {dataset_source} is not loaded"
            )

        if top_k < 1:
            top_k = 1

        model = self.models[dataset_source]
        scaler = self.scalers[dataset_source]

        # ---------------------------------------------------------------------
        # EXACT SAME FEATURE PREPROCESSING
        # ---------------------------------------------------------------------

        (
            X_raw,
            raw_values,
            feature_names,
            feature_labels,
        ) = self._extract_features(
            raw_features,
            dataset_source,
        )

        X_raw_array = np.asarray(
            X_raw,
            dtype=float,
        ).reshape(1, -1)

        # ---------------------------------------------------------------------
        # SAME SCALER USED BY THE MLP
        # ---------------------------------------------------------------------

        X_scaled = scaler.transform(
            X_raw_array
        )

        # ---------------------------------------------------------------------
        # VERIFY SAME MLP PREDICTION
        # ---------------------------------------------------------------------

        probabilities = model.predict_proba(
            X_scaled
        )[0]

        predicted_index = int(
            np.argmax(probabilities)
        )

        predicted_class = (
            model.classes_[predicted_index]
        )

        prediction_label = self._decode_label(
            dataset_source,
            predicted_class,
        )

        confidence = float(
            np.max(probabilities) * 100.0
        )

        # ---------------------------------------------------------------------
        # PERSISTED MLP LABEL SHOULD MATCH (non-fatal)
        # ---------------------------------------------------------------------

        prediction_mismatch = None

        if expected_prediction_label:
            expected_normalized = (
                self._normalize_label(
                    expected_prediction_label
                )
            )

            actual_normalized = (
                self._normalize_label(
                    prediction_label
                )
            )

            if expected_normalized != actual_normalized:
                # Simulated / injected events use synthetic features that may not
                # reproduce the exact class through the live MLP. Don't fail the
                # explanation for that; record the note and explain the model's
                # actual prediction on these features instead.
                prediction_mismatch = {
                    "persisted": expected_normalized,
                    "replayed": actual_normalized,
                    "dataset": dataset_source,
                }
                print(
                    "[XAI] Prediction mismatch (non-fatal): "
                    f"persisted={expected_normalized}, "
                    f"replayed={actual_normalized}, "
                    f"dataset={dataset_source}"
                )

        # ---------------------------------------------------------------------
        # GET/CACHE SHAP EXPLAINER
        # ---------------------------------------------------------------------

        explainer_obj = self._get_explainer(
            dataset_source
        )

        # ---------------------------------------------------------------------
        # CALCULATE SHAP
        # ---------------------------------------------------------------------

        shap_values = explainer_obj.shap_values(
            X_scaled
        )

        shap_vector = (
            self._extract_predicted_class_shap_values(
                shap_values=shap_values,
                predicted_class_index=predicted_index,
                n_features=len(feature_names),
            )
        )

        # ---------------------------------------------------------------------
        # BASE VALUE
        # ---------------------------------------------------------------------

        base_value = (
            self._extract_base_value(
                explainer_obj.expected_value,
                predicted_index,
            )
        )

        # ---------------------------------------------------------------------
        # BUILD FEATURE CONTRIBUTIONS
        # ---------------------------------------------------------------------

        contributions = []

        for index, feature_name in enumerate(
            feature_names
        ):
            shap_value = float(
                shap_vector[index]
            )

            absolute_value = abs(
                shap_value
            )

            if shap_value > 0:
                direction = "increases_prediction"
            elif shap_value < 0:
                direction = "decreases_prediction"
            else:
                direction = "neutral"

            contributions.append(
                {
                    "feature": feature_name,
                    "label": feature_labels.get(
                        feature_name,
                        feature_name,
                    ),
                    "shap_value": round(
                        shap_value,
                        6,
                    ),
                    "abs_value": round(
                        absolute_value,
                        6,
                    ),
                    "pct": 0.0,
                    "direction": direction,
                    "raw_value": raw_values[index],
                }
            )

        # ---------------------------------------------------------------------
        # PERCENTAGES
        # ---------------------------------------------------------------------

        total_absolute = sum(
            item["abs_value"]
            for item in contributions
        )

        if total_absolute > 0:
            for item in contributions:
                item["pct"] = round(
                    (
                        item["abs_value"]
                        / total_absolute
                    ) * 100.0,
                    1,
                )

        contributions.sort(
            key=lambda item: item["abs_value"],
            reverse=True,
        )

        top_features = contributions[
            :top_k
        ]

        # ---------------------------------------------------------------------
        # EXPLANATION TEXT
        # ---------------------------------------------------------------------

        explanation_text = (
            self._build_explanation_text(
                top_features,
                prediction_label,
                confidence,
            )
        )

        return {
            "method": "SHAP",
            "prediction_label": prediction_label,
            "confidence": round(
                confidence,
                2,
            ),
            "dataset_source": dataset_source,
            "top_features": top_features,
            "all_features": contributions,
            "explanation_text": explanation_text,
            "base_value": round(
                float(base_value),
                6,
            ),
            "feature_count": len(
                feature_names
            ),
            "model_classes": [
                str(value)
                for value in model.classes_
            ],
            "prediction_mismatch": prediction_mismatch,
        }

    # =========================================================================
    # SHAP EXPLAINER CREATION
    # =========================================================================

    def _get_explainer(
        self,
        dataset_source: str,
    ):
        """
        Cache one KernelExplainer per dataset.

        Important:
        the model receives SCALED features, therefore the SHAP background
        and explained sample are both scaled.
        """

        if dataset_source in self.explainers:
            return self.explainers[
                dataset_source
            ]

        model = self.models[
            dataset_source
        ]

        background = (
            self._build_background(
                dataset_source,
                num_samples=20,
            )
        )

        self.explainers[
            dataset_source
        ] = shap.KernelExplainer(
            model.predict_proba,
            background,
        )

        return self.explainers[
            dataset_source
        ]

    # =========================================================================
    # BACKGROUND DATA
    # =========================================================================

    def _build_background(
        self,
        dataset_source: str,
        num_samples: int = 20,
    ):
        """
        Build dataset-specific background rows using the same preprocessing
        as the MLP.
        """

        csv_path = os.path.abspath(
            os.path.join(
                MODEL_DIR,
                "..",
                "dataset",
                "unified_dataset.csv",
            )
        )

        raw_background = []

        try:
            with open(
                csv_path,
                "r",
                encoding="utf-8",
                errors="ignore",
            ) as file:

                reader = csv.DictReader(
                    file
                )

                for row in reader:

                    if (
                        row.get(
                            "dataset_source"
                        )
                        != dataset_source
                    ):
                        continue

                    try:

                        if dataset_source == "TON_IoT":
                            features, _ = (
                                self._extract_ton_features(
                                    row
                                )
                            )

                        elif dataset_source == "PhiUSIIL":
                            features, _ = (
                                self._extract_phi_features(
                                    row
                                )
                            )

                        elif dataset_source == "CERT":
                            features, _ = (
                                self._extract_cert_features(
                                    row
                                )
                            )

                        else:
                            continue

                        raw_background.append(
                            features
                        )

                    except Exception:
                        continue

                    if len(
                        raw_background
                    ) >= num_samples:
                        break

        except Exception as error:
            print(
                f"[XAI] Background loading failed "
                f"for {dataset_source}: {error}"
            )

        # ---------------------------------------------------------------------
        # Fallback background
        # ---------------------------------------------------------------------

        if not raw_background:

            feature_count = {
                "TON_IoT": 8,
                "PhiUSIIL": 10,
                "CERT": 7,
            }[dataset_source]

            raw_background = [
                [
                    0.0
                    for _ in range(
                        feature_count
                    )
                ]
            ]

        background_array = np.asarray(
            raw_background,
            dtype=float,
        )

        scaler = self.scalers[
            dataset_source
        ]

        try:
            return scaler.transform(
                background_array
            )

        except Exception as error:

            print(
                f"[XAI] Background scaling failed "
                f"for {dataset_source}: {error}"
            )

            return np.zeros(
                (
                    1,
                    background_array.shape[1],
                ),
                dtype=float,
            )

    # =========================================================================
    # FEATURE EXTRACTION
    # =========================================================================

    def _extract_features(
        self,
        raw_features: Dict,
        dataset_source: str,
    ) -> Tuple[
        List[float],
        List[float],
        List[str],
        Dict[str, str],
    ]:

        if dataset_source == "TON_IoT":

            features, raw_values = (
                self._extract_ton_features(
                    raw_features
                )
            )

            return (
                features,
                raw_values,
                TON_FEATURE_NAMES,
                TON_FEATURE_LABELS,
            )

        if dataset_source == "PhiUSIIL":

            features, raw_values = (
                self._extract_phi_features(
                    raw_features
                )
            )

            return (
                features,
                raw_values,
                PHI_FEATURE_NAMES,
                PHI_FEATURE_LABELS,
            )

        if dataset_source == "CERT":

            features, raw_values = (
                self._extract_cert_features(
                    raw_features
                )
            )

            return (
                features,
                raw_values,
                CERT_FEATURE_NAMES,
                CERT_FEATURE_LABELS,
            )

        raise ValueError(
            f"Unsupported dataset: {dataset_source}"
        )

    # =========================================================================
    # TON_IoT FEATURES
    # =========================================================================

    def _extract_ton_features(
        self,
        raw: Dict,
    ):
        proto_map = {
            "tcp": 6,
            "udp": 17,
            "icmp": 1,
        }

        proto_value = str(
            raw.get(
                "proto",
                "",
            )
        ).strip().lower()

        proto_num = proto_map.get(
            proto_value,
            0,
        )

        features = [
            self._safe_float(
                raw.get("src_port", 0)
            ),
            self._safe_float(
                raw.get("dst_port", 0)
            ),
            float(proto_num),
            self._safe_float(
                raw.get("duration", 0)
            ),
            self._safe_float(
                raw.get("src_bytes", 0)
            ),
            self._safe_float(
                raw.get("dst_bytes", 0)
            ),
            self._safe_float(
                raw.get("src_pkts", 0)
            ),
            self._safe_float(
                raw.get("dst_pkts", 0)
            ),
        ]

        return (
            features,
            list(features),
        )

    # =========================================================================
    # PhiUSIIL FEATURES
    # =========================================================================

    def _extract_phi_features(
        self,
        raw: Dict,
    ):
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
            self._safe_float(
                raw.get(
                    column,
                    0,
                )
            )
            for column in columns
        ]

        return (
            features,
            list(features),
        )

    # =========================================================================
    # CERT FEATURES
    # =========================================================================

    def _extract_cert_features(
        self,
        raw: Dict,
    ):
        hour = self._safe_float(
            raw.get(
                "hour",
                0,
            )
        )

        day_of_week = self._safe_float(
            raw.get(
                "dayofweek",
                0,
            )
        )

        is_after_hours = (
            1.0
            if (
                hour < 6
                or hour > 19
            )
            else 0.0
        )

        is_weekend = (
            1.0
            if day_of_week >= 5
            else 0.0
        )

        activity_map = {
            "Logon": 0,
            "Logoff": 1,
            "Connect": 2,
            "Disconnect": 3,
        }

        activity = str(
            raw.get(
                "activity",
                "",
            )
        ).strip()

        activity_type = float(
            activity_map.get(
                activity,
                0,
            )
        )

        user_value = str(
            raw.get(
                "user",
                "",
            )
        )

        try:
            user_enc = float(
                self.encoders[
                    "cert_user_le"
                ].transform(
                    [user_value]
                )[0]
            )
        except Exception:
            user_enc = 0.0

        pc_value = str(
            raw.get(
                "pc",
                "",
            )
        )

        try:
            pc_enc = float(
                self.encoders[
                    "cert_pc_le"
                ].transform(
                    [pc_value]
                )[0]
            )
        except Exception:
            pc_enc = 0.0

        features = [
            hour,
            day_of_week,
            is_after_hours,
            is_weekend,
            activity_type,
            user_enc,
            pc_enc,
        ]

        return (
            features,
            list(features),
        )

    # =========================================================================
    # SHAP OUTPUT HANDLING
    # =========================================================================

    def _extract_predicted_class_shap_values(
        self,
        shap_values,
        predicted_class_index: int,
        n_features: int,
    ):
        """
        Supports common SHAP output formats:

            list[class][sample][feature]
            ndarray[sample][feature][class]
            ndarray[class][sample][feature]
            ndarray[sample][feature]
            ndarray[feature]
        """

        # ---------------------------------------------------------------------
        # Multi-output legacy list
        # ---------------------------------------------------------------------

        if isinstance(
            shap_values,
            list,
        ):

            if not shap_values:
                raise ValueError(
                    "SHAP returned an empty list."
                )

            class_index = min(
                predicted_class_index,
                len(shap_values) - 1,
            )

            selected = np.asarray(
                shap_values[
                    class_index
                ]
            )

            if selected.ndim == 1:
                vector = selected

            elif selected.ndim == 2:
                vector = selected[0]

            else:
                raise ValueError(
                    "Unexpected SHAP list output shape: "
                    f"{selected.shape}"
                )

            return self._fit_vector_length(
                vector,
                n_features,
            )

        # ---------------------------------------------------------------------
        # ndarray outputs
        # ---------------------------------------------------------------------

        array = np.asarray(
            shap_values
        )

        # [samples, features, classes]
        if array.ndim == 3:

            if (
                array.shape[0] == 1
                and array.shape[1] == n_features
            ):
                class_index = min(
                    predicted_class_index,
                    array.shape[2] - 1,
                )

                vector = array[
                    0,
                    :,
                    class_index,
                ]

                return self._fit_vector_length(
                    vector,
                    n_features,
                )

            # [classes, samples, features]
            if (
                array.shape[1] == 1
                and array.shape[2] == n_features
            ):
                class_index = min(
                    predicted_class_index,
                    array.shape[0] - 1,
                )

                vector = array[
                    class_index,
                    0,
                    :,
                ]

                return self._fit_vector_length(
                    vector,
                    n_features,
                )

        # [samples, features]
        if array.ndim == 2:

            if array.shape[0] == 1:
                vector = array[0]

            elif array.shape[1] == n_features:
                vector = array[0]

            else:
                vector = array.reshape(-1)

            return self._fit_vector_length(
                vector,
                n_features,
            )

        # [features]
        if array.ndim == 1:

            return self._fit_vector_length(
                array,
                n_features,
            )

        raise ValueError(
            "Unsupported SHAP output shape: "
            f"{array.shape}"
        )

    @staticmethod
    def _fit_vector_length(
        vector,
        n_features,
    ):
        vector = np.asarray(
            vector,
            dtype=float,
        ).reshape(-1)

        if len(vector) == n_features:
            return vector

        if len(vector) > n_features:
            return vector[:n_features]

        padded = np.zeros(
            n_features,
            dtype=float,
        )

        padded[
            :len(vector)
        ] = vector

        return padded

    # =========================================================================
    # BASE VALUE
    # =========================================================================

    @staticmethod
    def _extract_base_value(
        expected_value,
        predicted_class_index: int,
    ):
        value = np.asarray(
            expected_value
        )

        if value.ndim == 0:
            return float(value)

        flat = value.reshape(-1)

        if len(flat) == 0:
            return 0.0

        index = min(
            predicted_class_index,
            len(flat) - 1,
        )

        return float(
            flat[index]
        )

    # =========================================================================
    # LABEL DECODING
    # =========================================================================

    def _decode_label(
        self,
        dataset_source: str,
        predicted_class,
    ):

        if dataset_source == "TON_IoT":

            encoder = self.encoders.get(
                "TON_IoT"
            )

            if encoder is None:
                return str(
                    predicted_class
                )

            decoded = encoder.inverse_transform(
                [predicted_class]
            )[0]

            return self._normalize_label(
                decoded
            )

        if dataset_source == "PhiUSIIL":

            try:
                return (
                    "Phishing"
                    if int(predicted_class) == 1
                    else "Normal"
                )
            except Exception:
                return str(
                    predicted_class
                )

        if dataset_source == "CERT":

            try:
                return (
                    "Insider Threat"
                    if int(predicted_class) == 1
                    else "Normal"
                )
            except Exception:
                return str(
                    predicted_class
                )

        return str(
            predicted_class
        )

    @staticmethod
    def _normalize_label(
        label,
    ):
        value = str(
            label
        ).strip().lower()

        if value == "ddos":
            return "DDoS"

        if value == "ransomware":
            return "Ransomware"

        if value == "phishing":
            return "Phishing"

        if value in {
            "insider",
            "insider threat",
            "insider_threat",
        }:
            return "Insider Threat"

        if value == "normal":
            return "Normal"

        # Do NOT silently convert an unknown class to Normal.
        return str(label)

    # =========================================================================
    # SAFE FLOAT
    # =========================================================================

    @staticmethod
    def _safe_float(
        value,
        default=0.0,
    ):
        if value is None:
            return default

        try:
            if pd.isna(value):
                return default
        except Exception:
            pass

        text = str(
            value
        ).strip()

        if text in {
            "",
            "-",
            "N/A",
            "n/a",
            "nan",
            "NaN",
            "None",
            "null",
        }:
            return default

        try:
            return float(
                text
            )

        except (
            ValueError,
            TypeError,
        ):
            return default

    # =========================================================================
    # EXPLANATION TEXT
    # =========================================================================

    @staticmethod
    def _build_explanation_text(
        top_features: List[Dict],
        label: str,
        confidence: float,
    ):
        if not top_features:
            return (
                f"The MLP classified this event as "
                f"{label} with "
                f"{confidence:.1f}% confidence, "
                f"but no significant SHAP contributors "
                f"were returned."
            )

        strongest = []

        for feature in top_features[:3]:
            strongest.append(
                (
                    f"{feature['label']} "
                    f"({feature['pct']:.1f}%)"
                )
            )

        drivers = ", ".join(
            strongest
        )

        return (
            f"The MLP classified this event as "
            f"{label} with "
            f"{confidence:.1f}% confidence. "
            f"The strongest SHAP contributors were: "
            f"{drivers}."
        )


# =============================================================================
# SINGLETON
# =============================================================================

explainer = ICDSExplainer()
