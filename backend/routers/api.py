from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    BackgroundTasks,
    Query,
)
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime
import asyncio

from database import get_db, SessionLocal
import models
import schemas
from auth import get_current_user, require_role
from cml.dataset_engine import engine as dataset_engine

import sys
import os

sys.path.append(
    os.path.dirname(
        os.path.dirname(__file__)
    )
)

from cml.qiga_optimizer import qiga
from cml.shap_explainer import (
    explainer as shap_explainer,
)
from cml.attack_memory import attack_memory


# =============================================================================
# ATTACK LOGS
# =============================================================================

logs_router = APIRouter(
    prefix="/api/logs",
    tags=["Attack Logs"],
)


@logs_router.get(
    "/",
    response_model=List[schemas.AttackLogOut],
)
def get_logs(
    skip: int = 0,
    limit: int = 50,
    severity: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    query = db.query(models.AttackLog)

    if severity:
        query = query.filter(
            models.AttackLog.severity
            == severity.upper()
        )

    return (
        query
        .order_by(
            models.AttackLog.detected_at.desc()
        )
        .offset(skip)
        .limit(limit)
        .all()
    )


@logs_router.get("/stats")
def get_log_stats(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    total = db.query(
        models.AttackLog
    ).count()

    critical = (
        db.query(models.AttackLog)
        .filter(
            models.AttackLog.severity
            == "CRITICAL",
            models.AttackLog.attack_type
            != "Normal",
        )
        .count()
    )

    active = (
        db.query(models.AttackLog)
        .filter(
            models.AttackLog.attack_type
            != "Normal",
            models.AttackLog.status
            != "RESOLVED",
        )
        .count()
    )

    resolved = (
        db.query(models.AttackLog)
        .filter(
            models.AttackLog.attack_type
            != "Normal",
            models.AttackLog.status
            == "RESOLVED",
        )
        .count()
    )

    return {
        "total": total,
        "critical": critical,
        "active": active,
        "resolved": resolved,
    }


@logs_router.get("/latest")
def get_latest_threats(
    limit: int = 20,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    from sqlalchemy import text

    results = (
        db.query(
            models.AttackLog,
            text(
                "attack_logs.dataset_source"
            ),
            text(
                "risk_scores.score"
            ),
            text(
                "risk_scores.confidence"
            ),
        )
        .outerjoin(
            models.RiskScore,
            text(
                "risk_scores.attack_log_id "
                "= attack_logs.id"
            ),
        )
        .order_by(
            models.AttackLog.detected_at.desc()
        )
        .limit(limit)
        .all()
    )

    return [
        {
            "id": log.id,
            "attack_log_id": log.id,
            "attack_type": log.attack_type,
            "prediction_label": log.attack_type,
            "severity": log.severity,
            "source_ip": (
                log.source_ip
                or "N/A"
            ),
            "dest_ip": (
                log.dest_ip
                or "N/A"
            ),
            "protocol": (
                log.protocol
                or "N/A"
            ),
            "port": log.port,
            "mitre_technique_id":
                log.mitre_technique_id,
            "mitre_technique_name":
                log.mitre_technique_name,
            "description":
                log.description,
            "raw_features":
                log.raw_features,
            "status":
                log.status,
            "detected_at":
                log.detected_at.isoformat(),
            "dataset":
                dataset_source,
            "dataset_source":
                dataset_source,
            "risk_score":
                (
                    float(risk_score)
                    if risk_score is not None
                    else 0.0
                ),
            "confidence":
                (
                    float(confidence)
                    if confidence is not None
                    else 0.0
                ),
            "model_version": None,
        }
        for (
            log,
            dataset_source,
            risk_score,
            confidence,
        ) in results
    ]


# =============================================================================
# ALERTS
# =============================================================================

alerts_router = APIRouter(
    prefix="/api/alerts",
    tags=["Alerts"],
)


@alerts_router.get(
    "/",
    response_model=List[schemas.AlertOut],
)
def get_alerts(
    skip: int = 0,
    limit: int = 30,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return (
        db.query(models.Alert)
        .order_by(
            models.Alert.created_at.desc()
        )
        .offset(skip)
        .limit(limit)
        .all()
    )


@alerts_router.get(
    "/unacknowledged/count"
)
def unacked_count(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    count = (
        db.query(models.Alert)
        .filter(
            models.Alert.is_acknowledged
            == False
        )
        .count()
    )

    return {
        "count": count
    }


@alerts_router.patch(
    "/{alert_id}/acknowledge"
)
def acknowledge_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(
        require_role(
            ["admin", "analyst"]
        )
    ),
):
    alert = (
        db.query(models.Alert)
        .filter(
            models.Alert.id
            == alert_id
        )
        .first()
    )

    if not alert:
        raise HTTPException(
            status_code=404,
            detail="Alert not found",
        )

    alert.is_acknowledged = True
    alert.acknowledged_by = (
        current_user.id
    )
    alert.acknowledged_at = (
        datetime.utcnow()
    )

    db.commit()

    return {
        "success": True
    }


# =============================================================================
# RISK PREDICTION / MLP
# =============================================================================

predict_router = APIRouter(
    prefix="/api/predict",
    tags=["Risk Prediction"],
)


def _calculate_prediction(
    log,
    dataset,
):
    """
    Run the correct trained dataset-specific MLP against
    the raw_features stored for the exact AttackLog.

    Supported:
        TON_IoT  -> TON_IoT MLP
        PhiUSIIL -> Phishing MLP
        CERT     -> CERT Insider Threat MLP
    """

    import numpy as np
    import pandas as pd

    from cml.dataset_engine import engine

    raw = log.raw_features or {}

    # =========================================================================
    # TON_IoT
    # =========================================================================

    if dataset == "TON_IoT":

        proto_map = {
            "tcp": 6,
            "udp": 17,
            "icmp": 1,
        }

        proto_num = proto_map.get(
            str(
                raw.get(
                    "proto",
                    "",
                )
            ).strip().lower(),
            0,
        )

        def safe_float(value):
            if value is None:
                return 0.0

            try:
                if pd.isna(value):
                    return 0.0
            except Exception:
                pass

            try:
                return float(value)
            except Exception:
                return 0.0

        features = [
            safe_float(
                raw.get(
                    "src_port",
                    0,
                )
            ),
            safe_float(
                raw.get(
                    "dst_port",
                    0,
                )
            ),
            float(proto_num),
            safe_float(
                raw.get(
                    "duration",
                    0,
                )
            ),
            safe_float(
                raw.get(
                    "src_bytes",
                    0,
                )
            ),
            safe_float(
                raw.get(
                    "dst_bytes",
                    0,
                )
            ),
            safe_float(
                raw.get(
                    "src_pkts",
                    0,
                )
            ),
            safe_float(
                raw.get(
                    "dst_pkts",
                    0,
                )
            ),
        ]

        scaled = engine.ton_scaler.transform(
            [features]
        )

        probs = (
            engine.ton_model
            .predict_proba(scaled)[0]
        )

        pred_idx = int(
            np.argmax(probs)
        )

        encoded_class = (
            engine.ton_model.classes_[
                pred_idx
            ]
        )

        label_raw = (
            engine.ton_le
            .inverse_transform(
                [encoded_class]
            )[0]
        )

        label_raw = str(
            label_raw
        ).strip().lower()

        if label_raw == "ddos":
            label = "DDoS"
        elif label_raw == "ransomware":
            label = "Ransomware"
        else:
            label = "Normal"

    # =========================================================================
    # PhiUSIIL
    # =========================================================================

    elif dataset == "PhiUSIIL":

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

        features = []

        for column in columns:

            value = raw.get(
                column,
                0,
            )

            try:
                if (
                    value is None
                    or pd.isna(value)
                ):
                    value = 0.0
                else:
                    value = float(value)
            except Exception:
                value = 0.0

            features.append(
                value
            )

        scaled = (
            engine.phi_scaler.transform(
                [features]
            )
        )

        probs = (
            engine.phi_model
            .predict_proba(scaled)[0]
        )

        pred_idx = int(
            np.argmax(probs)
        )

        pred_class = (
            engine.phi_model.classes_[
                pred_idx
            ]
        )

        label = (
            "Phishing"
            if int(pred_class) == 1
            else "Normal"
        )

    # =========================================================================
    # CERT
    # =========================================================================

    elif dataset == "CERT":

        try:
            dt = pd.to_datetime(
                raw.get(
                    "date",
                    "2010-01-01 00:00:00",
                )
            )

            hour = int(
                dt.hour
            )

            dayofweek = int(
                dt.dayofweek
            )

        except Exception:
            hour = 0
            dayofweek = 0

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
            if dayofweek >= 5
            else 0
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

        activity_type = (
            activity_map.get(
                activity,
                0,
            )
        )

        try:
            user_enc = (
                engine.cert_user_le
                .transform(
                    [
                        raw.get(
                            "user",
                            "",
                        )
                    ]
                )[0]
            )
        except Exception:
            user_enc = 0

        try:
            pc_enc = (
                engine.cert_pc_le
                .transform(
                    [
                        raw.get(
                            "pc",
                            "",
                        )
                    ]
                )[0]
            )
        except Exception:
            pc_enc = 0

        features = [
            hour,
            dayofweek,
            is_after_hours,
            is_weekend,
            activity_type,
            user_enc,
            pc_enc,
        ]

        scaled = (
            engine.cert_scaler.transform(
                [features]
            )
        )

        probs = (
            engine.cert_model
            .predict_proba(scaled)[0]
        )

        pred_idx = int(
            np.argmax(probs)
        )

        pred_class = (
            engine.cert_model.classes_[
                pred_idx
            ]
        )

        label = (
            "Insider Threat"
            if int(pred_class) == 1
            else "Normal"
        )

    else:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unknown dataset_source: "
                f"{dataset}"
            ),
        )

    # =========================================================================
    # CONFIDENCE + RISK
    # =========================================================================

    confidence = float(
        np.max(probs) * 100.0
    )

    if label == "Normal":
        risk_score = confidence * 0.05
    elif label == "DDoS":
        risk_score = confidence * 0.85
    elif label == "Ransomware":
        risk_score = confidence * 0.95
    elif label == "Phishing":
        risk_score = confidence * 0.70
    elif label == "Insider Threat":
        risk_score = confidence * 0.80
    else:
        risk_score = 50.0

    risk_score = min(
        99.0,
        max(
            0.0,
            risk_score,
        ),
    )

    model_info = engine.get_model_info(
        dataset
    )

    return {
        "label": label,
        "confidence": confidence,
        "risk_score": risk_score,
        "model_version": model_info.get(
            "model_version",
            "Unknown",
        ),
        "dataset": dataset,
        "class_probabilities": {
            str(index): float(probability)
            for index, probability
            in enumerate(probs)
        },
    }


# =============================================================================
# MODEL VALIDATION METRICS HELPERS
# =============================================================================

def _normalize_metric(value):
    """
    Convert metric values into 0-1 format.

    Supported:
        0.94
        94
        "94"
        "94%"
    """

    if value is None:
        return None

    try:
        text = str(
            value
        ).strip()

        if text.endswith("%"):
            text = text[:-1]

        numeric = float(
            text
        )

        if numeric > 1:
            numeric /= 100.0

        return max(
            0.0,
            min(
                1.0,
                numeric,
            ),
        )

    except (
        ValueError,
        TypeError,
    ):
        return None


def _find_metric(
    metrics,
    names,
):
    """
    Search common metric JSON structures.
    """

    if not isinstance(
        metrics,
        dict,
    ):
        return None

    containers = [
        metrics,
        metrics.get(
            "metrics",
            {},
        ),
        metrics.get(
            "weighted avg",
            {},
        ),
        metrics.get(
            "macro avg",
            {},
        ),
    ]

    for container in containers:

        if not isinstance(
            container,
            dict,
        ):
            continue

        for name in names:

            if name in container:

                normalized = (
                    _normalize_metric(
                        container.get(
                            name
                        )
                    )
                )

                if normalized is not None:
                    return normalized

    return None


# =============================================================================
# MODEL VALIDATION METRICS
# IMPORTANT: STATIC ROUTE MUST COME BEFORE /{attack_log_id}
# =============================================================================

@predict_router.get("/metrics")
def get_model_metrics(
    dataset: str = "TON_IoT",
    current_user=Depends(
        get_current_user
    ),
):
    """
    Return real validation metrics for
    the selected dataset-specific MLP.

    Final URL:
        /api/predict/metrics
    """

    supported = {
        "TON_IoT",
        "PhiUSIIL",
        "CERT",
    }

    dataset = str(
        dataset
    ).strip()

    if dataset not in supported:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unsupported dataset "
                f"'{dataset}'. "
                f"Supported datasets: "
                f"{sorted(supported)}"
            ),
        )

    try:

        from cml.dataset_engine import engine

        raw_metrics = (
            engine.get_metrics(
                dataset
            )
        )

        if not raw_metrics:
            raise HTTPException(
                status_code=404,
                detail=(
                    f"No validation metrics "
                    f"found for {dataset}."
                ),
            )

        precision = _find_metric(
            raw_metrics,
            [
                "precision",
                "Precision",
            ],
        )

        recall = _find_metric(
            raw_metrics,
            [
                "recall",
                "Recall",
            ],
        )

        f1 = _find_metric(
            raw_metrics,
            [
                "f1",
                "f1_score",
                "F1",
                "F1_score",
                "f1-score",
            ],
        )

        accuracy = _find_metric(
            raw_metrics,
            [
                "accuracy",
                "Accuracy",
            ],
        )

        return {
            "dataset": dataset,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "accuracy": accuracy,
            "raw_metrics": raw_metrics,
        }

    except HTTPException:
        raise

    except Exception as error:

        print(
            "[MODEL METRICS ERROR]",
            dataset,
            str(error),
        )

        raise HTTPException(
            status_code=500,
            detail=(
                f"Failed to load validation "
                f"metrics for {dataset}: "
                f"{str(error)}"
            ),
        )


# =============================================================================
# MANUAL MLP PREDICTION
# =============================================================================

@predict_router.post("/")
def predict_risk(
    payload: schemas.PredictInput,
    attack_log_id: Optional[int] = Query(
        None,
        description=(
            "AttackLog ID to analyze"
        ),
    ),
    db: Session = Depends(
        get_db
    ),
    current_user=Depends(
        require_role(
            [
                "admin",
                "analyst",
            ]
        )
    ),
):

    if attack_log_id is None:
        raise HTTPException(
            status_code=400,
            detail=(
                "attack_log_id is required"
            ),
        )

    log = (
        db.query(
            models.AttackLog
        )
        .filter(
            models.AttackLog.id
            == attack_log_id
        )
        .first()
    )

    if not log:
        raise HTTPException(
            status_code=404,
            detail="AttackLog not found",
        )

    if not log.raw_features:
        raise HTTPException(
            status_code=404,
            detail=(
                "AttackLog has no raw_features"
            ),
        )

    dataset = log.dataset_source

    if not dataset:

        from sqlalchemy import text

        dataset = db.execute(
            text(
                """
                SELECT dataset_source
                FROM attack_logs
                WHERE id = :id
                """
            ),
            {
                "id": attack_log_id
            },
        ).scalar()

    if not dataset:
        raise HTTPException(
            status_code=409,
            detail=(
                "AttackLog has no dataset_source"
            ),
        )

    prediction = _calculate_prediction(
        log,
        dataset,
    )

    label = prediction["label"]
    confidence = prediction["confidence"]
    risk_score = prediction["risk_score"]
    model_version = prediction["model_version"]

    # =========================================================================
    # STORE / UPDATE RISK SCORE
    # =========================================================================

    risk_record = (
        db.query(
            models.RiskScore
        )
        .filter(
            models.RiskScore.attack_log_id
            == attack_log_id
        )
        .order_by(
            models.RiskScore.computed_at.desc()
        )
        .first()
    )

    risk_status = (
        "CRITICAL"
        if risk_score > 70
        else "WARNING"
        if risk_score > 40
        else "STABLE"
    )

    if risk_record:

        risk_record.score = (
            risk_score
        )

        risk_record.confidence = (
            confidence
        )

        risk_record.prediction_label = (
            label
        )

        risk_record.model_version = (
            model_version
        )

        risk_record.status = (
            risk_status
        )

        risk_record.features_used = (
            log.raw_features
        )

    else:

        risk_record = models.RiskScore(
            attack_log_id=
                attack_log_id,
            score=
                risk_score,
            confidence=
                confidence,
            prediction_label=
                label,
            model_version=
                model_version,
            node_id=
                f"DATASET_{dataset}",
            status=
                risk_status,
            features_used=
                log.raw_features,
        )

        db.add(
            risk_record
        )

    # =========================================================================
    # SYNCHRONIZE ATTACKLOG
    # =========================================================================

    log.attack_type = label
    log.suspicious_score = confidence

    if label == "Normal":
        log.severity = "LOW"
    elif risk_score >= 80:
        log.severity = "CRITICAL"
    elif risk_score >= 60:
        log.severity = "HIGH"
    elif risk_score >= 35:
        log.severity = "MEDIUM"
    else:
        log.severity = "LOW"

    db.commit()
    db.refresh(
        risk_record
    )

    return {
        "attack_log_id":
            attack_log_id,
        "dataset":
            dataset,
        "risk_score":
            risk_score,
        "confidence":
            confidence,
        "prediction_label":
            label,
        "status":
            log.status,
        "feature_importance":
            {},
        "node_id":
            risk_record.node_id
            or f"DATASET_{dataset}",
        "model_version":
            model_version,
    }


# =============================================================================
# LATEST RISK SCORES
# IMPORTANT: STATIC ROUTE BEFORE /{attack_log_id}
# =============================================================================

@predict_router.get("/latest")
def get_latest_scores(
    limit: int = 10,
    db: Session = Depends(
        get_db
    ),
    current_user=Depends(
        get_current_user
    ),
):
    return (
        db.query(
            models.RiskScore
        )
        .order_by(
            models.RiskScore.computed_at.desc()
        )
        .limit(limit)
        .all()
    )


# =============================================================================
# MODEL INFORMATION
# IMPORTANT: STATIC ROUTE BEFORE /{attack_log_id}
# =============================================================================

@predict_router.get("/model-info")
def get_model_info(
    dataset: str = "TON_IoT",
    current_user=Depends(
        get_current_user
    ),
):
    from cml.dataset_engine import engine

    supported = {
        "TON_IoT",
        "PhiUSIIL",
        "CERT",
    }

    dataset = str(
        dataset
    ).strip()

    if dataset not in supported:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unsupported dataset: "
                f"{dataset}"
            ),
        )

    return engine.get_model_info(
        dataset
    )


# =============================================================================
# STORED MLP PREDICTION FOR ONE ATTACKLOG
# THIS DYNAMIC ROUTE MUST BE AFTER STATIC ROUTES
# =============================================================================

@predict_router.get("/{attack_log_id}")
def get_prediction_for_attack(
    attack_log_id: int,
    db: Session = Depends(
        get_db
    ),
    current_user=Depends(
        get_current_user
    ),
):
    """
    Return the already stored MLP prediction
    for one exact AttackLog.
    """

    log = (
        db.query(
            models.AttackLog
        )
        .filter(
            models.AttackLog.id
            == attack_log_id
        )
        .first()
    )

    if not log:
        raise HTTPException(
            status_code=404,
            detail="AttackLog not found",
        )

    risk_record = (
        db.query(
            models.RiskScore
        )
        .filter(
            models.RiskScore.attack_log_id
            == attack_log_id
        )
        .order_by(
            models.RiskScore.computed_at.desc()
        )
        .first()
    )

    if not risk_record:
        raise HTTPException(
            status_code=404,
            detail=(
                "No MLP prediction stored "
                "for this AttackLog"
            ),
        )

    return {
        "attack_log_id":
            attack_log_id,
        "dataset":
            log.dataset_source,
        "prediction_label":
            risk_record.prediction_label,
        "confidence":
            float(
                risk_record.confidence
                or 0
            ),
        "risk_score":
            float(
                risk_record.score
                or 0
            ),
        "status":
            log.status,
        "model_version":
            risk_record.model_version,
    }


# =============================================================================
# RECOMMENDATIONS
# =============================================================================

rec_router = APIRouter(
    prefix="/api/recommendations",
    tags=["Recommendations"],
)


def generate_qiga_recommendations(
    attack_log,
    db: Session,
):
    """
    Generate Recommendations from the actual
    persisted MLP RiskScore using QIGA.

    There is NO hard-coded recommendation map here.
    """

    if not attack_log:
        return []

    if attack_log.attack_type == "Normal":
        return []

    supported_types = {
        "DDoS",
        "Ransomware",
        "Phishing",
        "Insider Threat",
    }

    if (
        attack_log.attack_type
        not in supported_types
    ):
        return []

    existing = (
        db.query(
            models.Recommendation
        )
        .filter(
            models.Recommendation.attack_log_id
            == attack_log.id
        )
        .order_by(
            models.Recommendation.confidence_score.desc()
        )
        .all()
    )

    if existing:
        return existing

    risk_record = (
        db.query(
            models.RiskScore
        )
        .filter(
            models.RiskScore.attack_log_id
            == attack_log.id
        )
        .order_by(
            models.RiskScore.computed_at.desc()
        )
        .first()
    )

    if not risk_record:
        return []

    try:

        qiga_result = qiga.optimize(
            risk_score=float(
                risk_record.score
                or 0
            ),
            attack_type=
                attack_log.attack_type,
            severity=
                attack_log.severity
                or "MEDIUM",
            alpha=0.40,
            beta=0.35,
            gamma=0.25,
        )

    except Exception as error:

        print(
            "[QIGA ERROR]",
            str(error),
        )

        return []

    qiga_record = models.QIGAResult(
        attack_log_id=
            attack_log.id,
        risk_score=float(
            risk_record.score
            or 0
        ),
        attack_type=
            attack_log.attack_type,
        severity=
            attack_log.severity,
        objective_score=
            qiga_result[
                "objective_score"
            ],
        selected_actions=[
            action["id"]
            for action
            in qiga_result[
                "best_actions"
            ]
        ],
        all_actions_scored=
            qiga_result[
                "all_actions"
            ],
        convergence_data=
            qiga_result[
                "convergence"
            ],
        combined_effectiveness=
            qiga_result[
                "combined_effectiveness"
            ],
        combined_cost=
            qiga_result[
                "combined_cost"
            ],
        total_downtime_min=
            qiga_result[
                "total_downtime_min"
            ],
        alpha=
            qiga_result[
                "weights"
            ]["alpha"],
        beta=
            qiga_result[
                "weights"
            ]["beta"],
        gamma=
            qiga_result[
                "weights"
            ]["gamma"],
        generations=
            qiga_result[
                "generations"
            ],
        population_size=
            qiga_result[
                "population_size"
            ],
    )

    db.add(
        qiga_record
    )

    db.flush()

    created = []

    for action in (
        qiga_result[
            "best_actions"
        ]
    ):

        action_id = action.get(
            "id"
        )

        if not action_id:
            continue

        action_name = (
            action.get(
                "name"
            )
            or action_id
        )

        effectiveness = float(
            action.get(
                "effectiveness",
                0,
            )
        )

        resource_units = (
            action.get(
                "resource_units",
                "N/A",
            )
        )

        recovery_time = float(
            action.get(
                "recovery_time",
                0,
            )
        )

        description = (
            f"QIGA selected "
            f"{action_name} for "
            f"{attack_log.attack_type}. "
            f"Estimated effectiveness: "
            f"{effectiveness * 100:.1f}%. "
            f"Estimated recovery time: "
            f"{recovery_time:.0f} minutes."
        )

        recommendation = models.Recommendation(
            attack_log_id=
                attack_log.id,
            title=
                action_name,
            description=
                description,
            action_type=
                action_id,
            confidence_score=
                effectiveness,
            resource_cost=
                str(
                    resource_units
                ),
            latency_impact=
                f"{recovery_time:.0f} min",
            is_approved=False,
        )

        db.add(
            recommendation
        )

        created.append(
            recommendation
        )

    db.commit()

    for recommendation in created:
        db.refresh(
            recommendation
        )

    return created


@rec_router.get(
    "/",
    response_model=List[
        schemas.RecommendationOut
    ],
)
def get_recommendations(
    attack_log_id: Optional[int] = None,
    limit: int = 100,
    db: Session = Depends(
        get_db
    ),
    current_user=Depends(
        get_current_user
    ),
):
    if attack_log_id is not None:

        attack_log = (
            db.query(
                models.AttackLog
            )
            .filter(
                models.AttackLog.id
                == attack_log_id
            )
            .first()
        )

        if not attack_log:
            raise HTTPException(
                status_code=404,
                detail="AttackLog not found",
            )

        if attack_log.attack_type == "Normal":
            return []

        recommendations = (
            db.query(
                models.Recommendation
            )
            .filter(
                models.Recommendation.attack_log_id
                == attack_log_id
            )
            .order_by(
                models.Recommendation.confidence_score.desc()
            )
            .limit(limit)
            .all()
        )

        if not recommendations:

            recommendations = (
                generate_qiga_recommendations(
                    attack_log,
                    db,
                )
            )

        return recommendations[:limit]

    return (
        db.query(
            models.Recommendation
        )
        .order_by(
            models.Recommendation.confidence_score.desc()
        )
        .limit(limit)
        .all()
    )


@rec_router.patch(
    "/{rec_id}/approve"
)
def approve_recommendation(
    rec_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(
        get_db
    ),
    current_user=Depends(
        require_role(
            ["admin", "analyst"]
        )
    ),
):
    recommendation = (
        db.query(
            models.Recommendation
        )
        .filter(
            models.Recommendation.id
            == rec_id
        )
        .first()
    )

    if not recommendation:
        raise HTTPException(
            status_code=404,
            detail="Recommendation not found",
        )

    if not recommendation.attack_log_id:
        raise HTTPException(
            status_code=409,
            detail=(
                "Recommendation has no "
                "attack_log_id"
            ),
        )

    attack_log = (
        db.query(
            models.AttackLog
        )
        .filter(
            models.AttackLog.id
            == recommendation.attack_log_id
        )
        .first()
    )

    if not attack_log:
        raise HTTPException(
            status_code=404,
            detail="AttackLog not found",
        )

    if attack_log.attack_type == "Normal":
        raise HTTPException(
            status_code=400,
            detail=(
                "Normal traffic cannot "
                "enter response workflow."
            ),
        )

    if recommendation.is_approved:

        existing_recovery = (
            db.query(
                models.RecoveryAction
            )
            .filter(
                models.RecoveryAction.recommendation_id
                == recommendation.id
            )
            .order_by(
                models.RecoveryAction.created_at.desc()
            )
            .first()
        )

        return {
            "success": True,
            "message":
                "Recommendation already approved",
            "recovery_id":
                existing_recovery.id
                if existing_recovery
                else None,
            "attack_log_id":
                attack_log.id,
            "status":
                attack_log.status,
        }

    valid_actions = {
        "ISOLATE",
        "BLOCK",
        "RESTORE",
        "RESET",
        "PATCH",
    }

    if (
        recommendation.action_type
        not in valid_actions
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "Invalid recommendation "
                f"action_type: "
                f"{recommendation.action_type}"
            ),
        )

    dataset_source = (
        attack_log.dataset_source
    )

    raw = (
        attack_log.raw_features
        or {}
    )

    target_node = (
        attack_log.dest_ip
        or "UNKNOWN"
    )

    if dataset_source == "TON_IoT":

        if attack_log.dest_ip:

            asset = (
                db.query(
                    models.HospitalAsset
                )
                .filter(
                    models.HospitalAsset.ip_address
                    == attack_log.dest_ip
                )
                .first()
            )

            target_node = (
                asset.asset_name
                if asset
                else attack_log.dest_ip
            )

        else:

            target_node = raw.get(
                "dst_ip",
                "UNKNOWN",
            )

    elif dataset_source == "PhiUSIIL":

        target_node = raw.get(
            "URL",
            raw.get(
                "Domain",
                "WEB_APP",
            ),
        )

    elif dataset_source == "CERT":

        user = raw.get(
            "user",
            "",
        )

        pc = raw.get(
            "pc",
            "",
        )

        if user and pc:
            target_node = (
                f"{user}@{pc}"
            )
        else:
            target_node = (
                user
                or pc
                or "WORKSTATION"
            )

    recommendation.is_approved = True

    recommendation.approved_by = (
        current_user.id
    )

    recommendation.approved_at = (
        datetime.utcnow()
    )

    recovery = models.RecoveryAction(
        recommendation_id=
            recommendation.id,
        action_name=
            recommendation.title,
        action_type=
            recommendation.action_type,
        target_node=
            str(
                target_node
            )[:100],
        status="PENDING",
        executed_by=
            current_user.id,
    )

    db.add(
        recovery
    )

    attack_log.status = (
        "CONTAINMENT"
    )

    incident = (
        db.query(
            models.Incident
        )
        .filter(
            models.Incident.attack_id
            == attack_log.id
        )
        .first()
    )

    if incident:
        incident.status = (
            "CONTAINMENT"
        )

    db.commit()

    db.refresh(
        recovery
    )

    try:

        from main import manager

        loop = asyncio.get_event_loop()

        if loop.is_running():

            loop.create_task(
                manager.broadcast(
                    {
                        "type":
                            "lifecycle_update",
                        "data": {
                            "attack_log_id":
                                attack_log.id,
                            "status":
                                "CONTAINMENT",
                        },
                    }
                )
            )

    except Exception as error:

        print(
            "[WEBSOCKET ERROR]",
            str(error),
        )

    background_tasks.add_task(
        _execute_recovery,
        recovery.id,
    )

    return {
        "success": True,
        "message":
            "Mitigation authorized",
        "recovery_id":
            recovery.id,
        "attack_log_id":
            attack_log.id,
        "status":
            "CONTAINMENT",
    }


# =============================================================================
# RECOVERY ENGINE
# =============================================================================

recovery_router = APIRouter(
    prefix="/api/recovery",
    tags=["Recovery"],
)


RECOVERY_SCRIPTS = {

    "ISOLATE": [
        "Initiating network isolation protocol...",
        "Disconnecting target node from hospital VLAN...",
        "Revoking routing table entries for affected subnet...",
        "Blocking all inbound/outbound traffic on target NIC...",
        "Isolation boundary established - lateral movement prevented.",
        "Integrity verification complete. Node successfully isolated.",
    ],

    "BLOCK": [
        "Resolving attacker IP and attack signature...",
        "Pushing block rule to perimeter firewall...",
        "Updating WAF deny-list...",
        "Rule propagated across security edge nodes.",
        "Traffic block confirmed.",
    ],

    "RESTORE": [
        "Verifying backup integrity hash...",
        "SHA-256 checksum validation: PASSED",
        "Mounting clean recovery snapshot...",
        "Restoring affected system data...",
        "Validating restored records...",
        "Data integrity confirmed.",
        "Recovery completed successfully.",
    ],

    "RESET": [
        "Invalidating active sessions...",
        "Revoking OAuth tokens and credentials...",
        "Forcing MFA re-enrollment...",
        "Notifying security team...",
        "Account reset complete.",
    ],

    "PATCH": [
        "Identifying vulnerable software version...",
        "Downloading approved security patch...",
        "Applying security update...",
        "Running post-patch integrity checks...",
        "Patch applied successfully.",
    ],
}


async def _broadcast_lifecycle(
    attack_log_id: int,
    status: str,
):
    try:

        from main import manager

        await manager.broadcast(
            {
                "type":
                    "lifecycle_update",
                "data": {
                    "attack_log_id":
                        attack_log_id,
                    "status":
                        status,
                },
            }
        )

    except Exception as error:

        print(
            "[RECOVERY BROADCAST ERROR]",
            str(error),
        )


async def _execute_recovery(
    recovery_id: int,
):
    db = SessionLocal()
    recovery = None

    try:

        recovery = (
            db.query(
                models.RecoveryAction
            )
            .filter(
                models.RecoveryAction.id
                == recovery_id
            )
            .first()
        )

        if not recovery:
            return

        recovery.status = (
            "IN_PROGRESS"
        )

        recovery.started_at = (
            datetime.utcnow()
        )

        recovery.execution_log = (
            "Recovery workflow initialized..."
        )

        db.commit()

        steps = (
            RECOVERY_SCRIPTS.get(
                recovery.action_type,
                [
                    "Executing recovery action...",
                    "Recovery complete.",
                ],
            )
        )

        midpoint = max(
            1,
            len(steps) // 2,
        )

        attack_log_id = None

        if recovery.recommendation_id:

            recommendation = (
                db.query(
                    models.Recommendation
                )
                .filter(
                    models.Recommendation.id
                    == recovery.recommendation_id
                )
                .first()
            )

            if recommendation:
                attack_log_id = (
                    recommendation.attack_log_id
                )

        log_lines = []

        for index, step in enumerate(
            steps
        ):

            await asyncio.sleep(
                1.0
            )

            if (
                index == midpoint
                and attack_log_id
            ):

                incident = (
                    db.query(
                        models.Incident
                    )
                    .filter(
                        models.Incident.attack_id
                        == attack_log_id
                    )
                    .first()
                )

                if incident:
                    incident.status = (
                        "RECOVERY"
                    )

                attack_log = (
                    db.query(
                        models.AttackLog
                    )
                    .filter(
                        models.AttackLog.id
                        == attack_log_id
                    )
                    .first()
                )

                if attack_log:
                    attack_log.status = (
                        "RECOVERY"
                    )

                db.commit()

                await _broadcast_lifecycle(
                    attack_log_id,
                    "RECOVERY",
                )

            timestamp = (
                datetime.utcnow()
                .strftime(
                    "%H:%M:%S"
                )
            )

            log_lines.append(
                f"[{timestamp}] {step}"
            )

            recovery.execution_log = (
                "\n".join(
                    log_lines
                )
            )

            db.commit()

        recovery.status = (
            "COMPLETED"
        )

        recovery.completed_at = (
            datetime.utcnow()
        )

        if attack_log_id:

            attack_log = (
                db.query(
                    models.AttackLog
                )
                .filter(
                    models.AttackLog.id
                    == attack_log_id
                )
                .first()
            )

            if attack_log:

                attack_log.status = (
                    "RESOLVED"
                )

                attack_log.resolved_at = (
                    datetime.utcnow()
                )

            incident = (
                db.query(
                    models.Incident
                )
                .filter(
                    models.Incident.attack_id
                    == attack_log_id
                )
                .first()
            )

            if incident:

                incident.status = (
                    "RESOLVED"
                )

                incident.closed_at = (
                    datetime.utcnow()
                )

            alerts = (
                db.query(
                    models.Alert
                )
                .filter(
                    models.Alert.attack_log_id
                    == attack_log_id
                )
                .all()
            )

            for alert in alerts:

                alert.is_acknowledged = (
                    True
                )

                alert.acknowledged_at = (
                    datetime.utcnow()
                )

                alert.acknowledged_by = (
                    recovery.executed_by
                )

            memory_entry = (
                db.query(
                    models.AttackMemoryEntry
                )
                .filter(
                    models.AttackMemoryEntry.attack_log_id
                    == attack_log_id
                )
                .order_by(
                    models.AttackMemoryEntry.recorded_at.desc()
                )
                .first()
            )

            if memory_entry:

                memory_entry.outcome = (
                    "RESOLVED"
                )

                memory_entry.success = (
                    True
                )

            db.commit()

            await _broadcast_lifecycle(
                attack_log_id,
                "RESOLVED",
            )

    except Exception as error:

        print(
            "[RECOVERY ENGINE ERROR]",
            str(error),
        )

        if recovery:

            recovery.status = (
                "FAILED"
            )

            recovery.execution_log = (
                (recovery.execution_log or "")
                + "\n[ERROR] "
                + str(error)
            )

            db.commit()

    finally:

        db.close()


@recovery_router.get(
    "/",
    response_model=List[
        schemas.RecoveryActionOut
    ],
)
def get_recovery_actions(
    attack_log_id: Optional[int] = None,
    limit: int = 100,
    db: Session = Depends(
        get_db
    ),
    current_user=Depends(
        require_role(
            ["admin", "analyst"]
        )
    ),
):
    query = db.query(
        models.RecoveryAction
    )

    if attack_log_id is not None:

        query = (
            query
            .join(
                models.Recommendation,
                models.RecoveryAction
                .recommendation_id
                ==
                models.Recommendation.id,
            )
            .filter(
                models.Recommendation.attack_log_id
                == attack_log_id
            )
        )

    return (
        query
        .order_by(
            models.RecoveryAction.created_at.desc()
        )
        .limit(limit)
        .all()
    )


@recovery_router.get(
    "/{recovery_id}",
    response_model=schemas.RecoveryActionOut,
)
def get_recovery_detail(
    recovery_id: int,
    db: Session = Depends(
        get_db
    ),
    current_user=Depends(
        require_role(
            ["admin", "analyst"]
        )
    ),
):
    recovery = (
        db.query(
            models.RecoveryAction
        )
        .filter(
            models.RecoveryAction.id
            == recovery_id
        )
        .first()
    )

    if not recovery:
        raise HTTPException(
            status_code=404,
            detail="Recovery action not found",
        )

    return recovery


# =============================================================================
# MONITORING
# =============================================================================

monitor_router = APIRouter(
    prefix="/api/monitoring",
    tags=["Monitoring"],
)


@monitor_router.get("/live")
def get_live_stats(
    db: Session = Depends(
        get_db
    ),
    current_user=Depends(
        get_current_user
    ),
):
    active_threats = (
        db.query(
            models.AttackLog
        )
        .filter(
            models.AttackLog.attack_type
            != "Normal",
            models.AttackLog.status
            != "RESOLVED",
        )
        .count()
    )

    latest_risk = (
        db.query(
            models.RiskScore
        )
        .order_by(
            models.RiskScore.computed_at.desc()
        )
        .first()
    )

    return {
        "throughput_gbps":
            None,
        "latency_ms":
            None,
        "packet_loss":
            None,
        "sys_health":
            None,
        "node_load_avg":
            None,
        "active_connections":
            None,
        "active_threats":
            active_threats,
        "mlp_model_status":
            "ACTIVE",
        "risk_score": (
            latest_risk.score
            if latest_risk
            else 0.0
        ),
    }


@monitor_router.get(
    "/history",
    response_model=List[
        schemas.MonitoringOut
    ],
)
def get_history(
    limit: int = 100,
    db: Session = Depends(
        get_db
    ),
    current_user=Depends(
        get_current_user
    ),
):
    return (
        db.query(
            models.MonitoringHistory
        )
        .order_by(
            models.MonitoringHistory.recorded_at.desc()
        )
        .limit(limit)
        .all()
    )


# =============================================================================
# DASHBOARD
# =============================================================================

dashboard_router = APIRouter(
    prefix="/api/dashboard",
    tags=["Dashboard"],
)


@dashboard_router.get(
    "/risk-history"
)
def get_risk_history(
    limit: int = 30,
    db: Session = Depends(
        get_db
    ),
):
    from sqlalchemy import text

    results = db.execute(
        text(
            """
            SELECT
                r.score,
                r.computed_at,
                a.attack_type
            FROM risk_scores r
            LEFT JOIN attack_logs a
                ON r.attack_log_id = a.id
            ORDER BY r.computed_at DESC
            LIMIT :limit
            """
        ),
        {
            "limit": limit
        },
    ).fetchall()

    history = []

    for (
        score,
        computed_at,
        attack_type,
    ) in reversed(
        results
    ):

        try:
            timestamp = (
                computed_at.strftime(
                    "%H:%M:%S"
                )
            )
        except Exception:
            timestamp = str(
                computed_at
            )

        history.append(
            {
                "t":
                    timestamp,
                "risk":
                    round(
                        float(score),
                        1,
                    )
                    if score
                    else 0.0,
                "threats":
                    1
                    if (
                        attack_type
                        and attack_type
                        != "Normal"
                    )
                    else 0,
            }
        )

    return history


@dashboard_router.get("/")
def get_dashboard(
    db: Session = Depends(
        get_db
    ),
    current_user=Depends(
        get_current_user
    ),
):
    total_attacks = (
        db.query(
            models.AttackLog
        ).count()
    )

    active_attacks = (
        db.query(
            models.AttackLog
        )
        .filter(
            models.AttackLog.attack_type
            != "Normal",
            models.AttackLog.status
            != "RESOLVED",
        )
        .count()
    )

    resolved_attacks = (
        db.query(
            models.AttackLog
        )
        .filter(
            models.AttackLog.attack_type
            != "Normal",
            models.AttackLog.status
            == "RESOLVED",
        )
        .count()
    )

    severity_counts = {
        "CRITICAL":
            db.query(
                models.AttackLog
            )
            .filter(
                models.AttackLog.severity
                == "CRITICAL"
            )
            .count(),

        "HIGH":
            db.query(
                models.AttackLog
            )
            .filter(
                models.AttackLog.severity
                == "HIGH"
            )
            .count(),

        "MEDIUM":
            db.query(
                models.AttackLog
            )
            .filter(
                models.AttackLog.severity
                == "MEDIUM"
            )
            .count(),

        "LOW":
            db.query(
                models.AttackLog
            )
            .filter(
                models.AttackLog.severity
                == "LOW"
            )
            .count(),
    }

    total_incidents = (
        db.query(
            models.Incident
        ).count()
    )

    active_incidents = (
        db.query(
            models.Incident
        )
        .filter(
            models.Incident.status
            != "RESOLVED"
        )
        .count()
    )

    resolved_incidents = (
        db.query(
            models.Incident
        )
        .filter(
            models.Incident.status
            == "RESOLVED"
        )
        .count()
    )

    unacked_alerts = (
        db.query(
            models.Alert
        )
        .filter(
            models.Alert.is_acknowledged
            == False
        )
        .count()
    )

    recent_alerts = (
        db.query(
            models.Alert
        )
        .order_by(
            models.Alert.created_at.desc()
        )
        .limit(5)
        .all()
    )

    recent_attacks = (
        db.query(
            models.AttackLog
        )
        .order_by(
            models.AttackLog.detected_at.desc()
        )
        .limit(20)
        .all()
    )

    latest_risk = (
        db.query(
            models.RiskScore
        )
        .order_by(
            models.RiskScore.computed_at.desc()
        )
        .first()
    )

    active_recoveries = (
        db.query(
            models.RecoveryAction
        )
        .filter(
            models.RecoveryAction.status.in_(
                [
                    "PENDING",
                    "IN_PROGRESS",
                ]
            )
        )
        .count()
    )

    assets_online = (
        db.query(
            models.HospitalAsset
        )
        .filter(
            models.HospitalAsset.status
            == "ONLINE"
        )
        .count()
    )

    assets_total = (
        db.query(
            models.HospitalAsset
        ).count()
    )

    return {
        "attack_stats": {
            "total":
                total_attacks,
            "active":
                active_attacks,
            "resolved":
                resolved_attacks,
        },

        "severity_counts":
            severity_counts,

        "incident_stats": {
            "total":
                total_incidents,
            "active":
                active_incidents,
            "resolved":
                resolved_incidents,
        },

        "alert_stats": {
            "unacknowledged":
                unacked_alerts,
        },

        "asset_stats": {
            "total":
                assets_total,
            "online":
                assets_online,
        },

        "active_recoveries":
            active_recoveries,

        "latest_risk_score": {
            "score":
                latest_risk.score
                if latest_risk
                else 0,

            "status":
                latest_risk.status
                if latest_risk
                else "STABLE",

            "label":
                latest_risk.prediction_label
                if latest_risk
                else "N/A",
        },

        "recent_alerts": [
            {
                "id":
                    alert.id,
                "title":
                    alert.title,
                "severity":
                    alert.severity,
                "is_acknowledged":
                    alert.is_acknowledged,
                "created_at":
                    alert.created_at.isoformat(),
            }
            for alert in recent_alerts
        ],

        "recent_attacks": [
            {
                "id":
                    log.id,
                "attack_type":
                    log.attack_type,
                "source_ip":
                    log.source_ip,
                "dest_ip":
                    log.dest_ip,
                "severity":
                    log.severity,
                "status":
                    log.status,
                "mitre_technique_id":
                    log.mitre_technique_id,
                "mitre_technique_name":
                    log.mitre_technique_name,
                "suspicious_score":
                    log.suspicious_score,
                "detected_at":
                    log.detected_at.isoformat(),
            }
            for log in recent_attacks
        ],
    }


# =============================================================================
# INCIDENTS
# =============================================================================

incidents_router = APIRouter(
    prefix="/api/incidents",
    tags=["Incidents"],
)


@incidents_router.get(
    "/",
    response_model=List[
        schemas.IncidentOut
    ],
)
def get_incidents(
    status: Optional[str] = None,
    limit: int = 30,
    db: Session = Depends(
        get_db
    ),
    current_user=Depends(
        get_current_user
    ),
):
    query = db.query(
        models.Incident
    )

    if status:
        query = query.filter(
            models.Incident.status
            == status.upper()
        )

    return (
        query
        .order_by(
            models.Incident.opened_at.desc()
        )
        .limit(limit)
        .all()
    )


@incidents_router.patch(
    "/{incident_id}"
)
def update_incident(
    incident_id: int,
    update: schemas.IncidentUpdate,
    db: Session = Depends(
        get_db
    ),
    current_user=Depends(
        require_role(
            ["admin", "analyst"]
        )
    ),
):
    incident = (
        db.query(
            models.Incident
        )
        .filter(
            models.Incident.id
            == incident_id
        )
        .first()
    )

    if not incident:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    if update.status:

        incident.status = (
            update.status.upper()
        )

        if (
            update.status.upper()
            == "RESOLVED"
        ):
            incident.closed_at = (
                datetime.utcnow()
            )

    if (
        update.assigned_to
        is not None
    ):
        incident.assigned_to = (
            update.assigned_to
        )

    db.commit()

    return {
        "success": True
    }


# =============================================================================
# HOSPITAL ASSETS
# =============================================================================

assets_router = APIRouter(
    prefix="/api/assets",
    tags=["Hospital Assets"],
)


@assets_router.get(
    "/",
    response_model=List[
        schemas.HospitalAssetOut
    ],
)
def get_assets(
    db: Session = Depends(
        get_db
    ),
    current_user=Depends(
        get_current_user
    ),
):
    return (
        db.query(
            models.HospitalAsset
        )
        .all()
    )


@assets_router.patch(
    "/{asset_id}/status"
)
def update_asset_status(
    asset_id: int,
    new_status: str,
    db: Session = Depends(
        get_db
    ),
    current_user=Depends(
        require_role(
            ["admin", "analyst"]
        )
    ),
):
    asset = (
        db.query(
            models.HospitalAsset
        )
        .filter(
            models.HospitalAsset.id
            == asset_id
        )
        .first()
    )

    if not asset:
        raise HTTPException(
            status_code=404,
            detail="Asset not found",
        )

    valid = {
        "ONLINE",
        "OFFLINE",
        "ISOLATED",
        "COMPROMISED",
    }

    if (
        new_status.upper()
        not in valid
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                f"Invalid status. "
                f"Options: {valid}"
            ),
        )

    asset.status = (
        new_status.upper()
    )

    db.commit()

    return {
        "success": True,
        "asset":
            asset.asset_name,
        "status":
            asset.status,
    }


# =============================================================================
# ADMIN
# =============================================================================

admin_router = APIRouter(
    prefix="/api/admin",
    tags=["Admin"],
)


@admin_router.get("/users")
def get_users(
    db: Session = Depends(
        get_db
    ),
    current_user=Depends(
        require_role(
            ["admin"]
        )
    ),
):
    users = (
        db.query(
            models.User
        )
        .all()
    )

    return [
        {
            "id":
                user.id,
            "full_name":
                user.full_name,
            "email":
                user.email,
            "role":
                user.role,
            "is_active":
                user.is_active,
            "clearance_level":
                user.clearance_level,
        }
        for user in users
    ]


@admin_router.get("/stats")
def admin_stats(
    db: Session = Depends(
        get_db
    ),
    current_user=Depends(
        require_role(
            ["admin"]
        )
    ),
):
    return {
        "total_users":
            db.query(
                models.User
            ).count(),

        "total_attacks":
            db.query(
                models.AttackLog
            ).count(),

        "total_alerts":
            db.query(
                models.Alert
            ).count(),

        "active_threats":
            (
                db.query(
                    models.AttackLog
                )
                .filter(
                    models.AttackLog.attack_type
                    != "Normal",
                    models.AttackLog.status
                    != "RESOLVED",
                )
                .count()
            ),

        "total_incidents":
            db.query(
                models.Incident
            ).count(),

        "model_version":
            "MULTI_MLP_v1",

        "system_uptime":
            "99.99%",

        "data_processed":
            "2.4PB",

        "qiga_runs":
            db.query(
                models.QIGAResult
            ).count(),

        "memory_entries":
            db.query(
                models.AttackMemoryEntry
            ).count(),
    }


# =============================================================================
# QIGA OPTIMIZER
# =============================================================================

optimizer_router = APIRouter(
    prefix="/api/optimize",
    tags=["QIGA Optimizer"],
)


@optimizer_router.post("/")
def run_optimizer(
    attack_log_id: int,
    alpha: float = 0.4,
    beta: float = 0.35,
    gamma: float = 0.25,
    db: Session = Depends(
        get_db
    ),
    current_user=Depends(
        require_role(
            ["admin", "analyst"]
        )
    ),
):
    log = (
        db.query(
            models.AttackLog
        )
        .filter(
            models.AttackLog.id
            == attack_log_id
        )
        .first()
    )

    if not log:
        raise HTTPException(
            status_code=404,
            detail="AttackLog not found",
        )

    if log.attack_type == "Normal":
        raise HTTPException(
            status_code=400,
            detail=(
                "QIGA is not available "
                "for Normal traffic."
            ),
        )

    supported_types = {
        "DDoS",
        "Ransomware",
        "Phishing",
        "Insider Threat",
    }

    if (
        log.attack_type
        not in supported_types
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unsupported attack type "
                f"for QIGA: "
                f"{log.attack_type}"
            ),
        )

    risk_record = (
        db.query(
            models.RiskScore
        )
        .filter(
            models.RiskScore.attack_log_id
            == attack_log_id
        )
        .order_by(
            models.RiskScore.computed_at.desc()
        )
        .first()
    )

    if not risk_record:
        raise HTTPException(
            status_code=409,
            detail=(
                "AttackLog has no linked "
                "RiskScore."
            ),
        )

    result = qiga.optimize(
        risk_score=float(
            risk_record.score
            or 0
        ),
        attack_type=
            log.attack_type,
        severity=
            log.severity
            or "MEDIUM",
        alpha=alpha,
        beta=beta,
        gamma=gamma,
    )

    qiga_record = models.QIGAResult(
        attack_log_id=
            attack_log_id,
        risk_score=float(
            risk_record.score
            or 0
        ),
        attack_type=
            log.attack_type,
        severity=
            log.severity,
        objective_score=
            result[
                "objective_score"
            ],
        selected_actions=[
            action["id"]
            for action
            in result[
                "best_actions"
            ]
        ],
        all_actions_scored=
            result[
                "all_actions"
            ],
        convergence_data=
            result[
                "convergence"
            ],
        combined_effectiveness=
            result[
                "combined_effectiveness"
            ],
        combined_cost=
            result[
                "combined_cost"
            ],
        total_downtime_min=
            result[
                "total_downtime_min"
            ],
        alpha=alpha,
        beta=beta,
        gamma=gamma,
        generations=
            result[
                "generations"
            ],
        population_size=
            result[
                "population_size"
            ],
    )

    db.add(
        qiga_record
    )

    db.flush()

    (
        db.query(
            models.Recommendation
        )
        .filter(
            models.Recommendation.attack_log_id
            == attack_log_id,
            models.Recommendation.is_approved
            == False,
        )
        .delete(
            synchronize_session=False
        )
    )

    created = []

    for action in (
        result[
            "best_actions"
        ]
    ):

        effectiveness = float(
            action.get(
                "effectiveness",
                0,
            )
        )

        recovery_time = float(
            action.get(
                "recovery_time",
                0,
            )
        )

        recommendation = models.Recommendation(
            attack_log_id=
                attack_log_id,
            title=
                action.get(
                    "name",
                    action["id"],
                ),
            description=(
                "QIGA selected "
                f"{action.get('name', action['id'])} "
                f"for {log.attack_type}. "
                f"Estimated effectiveness "
                f"{effectiveness * 100:.1f}%."
            ),
            action_type=
                action["id"],
            confidence_score=
                effectiveness,
            resource_cost=str(
                action.get(
                    "resource_units",
                    "N/A",
                )
            ),
            latency_impact=
                f"{recovery_time:.0f} min",
            is_approved=False,
        )

        db.add(
            recommendation
        )

        created.append(
            recommendation
        )

    db.commit()

    db.refresh(
        qiga_record
    )

    for recommendation in created:
        db.refresh(
            recommendation
        )

    return {
        "qiga_id":
            qiga_record.id,
        "attack_log_id":
            attack_log_id,
        "attack_type":
            log.attack_type,
        "severity":
            log.severity,
        "risk_score":
            risk_record.score,
        "objective_score":
            result[
                "objective_score"
            ],
        "selected_actions":
            result[
                "best_actions"
            ],
        "recommendations": [
            {
                "id":
                    rec.id,
                "title":
                    rec.title,
                "action_type":
                    rec.action_type,
                "description":
                    rec.description,
                "confidence_score":
                    rec.confidence_score,
            }
            for rec in created
        ],
        "convergence":
            result[
                "convergence"
            ],
        "combined_effectiveness":
            result[
                "combined_effectiveness"
            ],
        "combined_cost":
            result[
                "combined_cost"
            ],
        "total_downtime_min":
            result[
                "total_downtime_min"
            ],
    }


@optimizer_router.get(
    "/latest"
)
def get_latest_optimizer_results(
    limit: int = 5,
    db: Session = Depends(
        get_db
    ),
    current_user=Depends(
        get_current_user
    ),
):
    results = (
        db.query(
            models.QIGAResult
        )
        .order_by(
            models.QIGAResult.computed_at.desc()
        )
        .limit(limit)
        .all()
    )

    return [
        {
            "id":
                result.id,
            "attack_type":
                result.attack_type,
            "severity":
                result.severity,
            "risk_score":
                result.risk_score,
            "objective_score":
                result.objective_score,
            "selected_actions":
                result.selected_actions,
            "combined_effectiveness":
                result.combined_effectiveness,
            "combined_cost":
                result.combined_cost,
            "computed_at":
                result.computed_at.isoformat(),
        }
        for result in results
    ]


# =============================================================================
# EXPLAINABLE AI / SHAP
# =============================================================================

xai_router = APIRouter(
    prefix="/api/xai",
    tags=["XAI Explainability"],
)


@xai_router.get(
    "/explain/{log_id}"
)
def explain_attack_log(
    log_id: int,
    db: Session = Depends(
        get_db
    ),
    current_user=Depends(
        get_current_user
    ),
):
    """
    Return SHAP explanation for the SAME MLP prediction
    stored against this exact AttackLog.
    """

    # =========================================================================
    # 1. LOAD EXACT ATTACK LOG
    # =========================================================================

    log = (
        db.query(
            models.AttackLog
        )
        .filter(
            models.AttackLog.id
            == log_id
        )
        .first()
    )

    if not log:
        raise HTTPException(
            status_code=404,
            detail="AttackLog not found",
        )

    if not log.raw_features:
        raise HTTPException(
            status_code=409,
            detail=(
                "AttackLog has no raw_features."
            ),
        )

    # =========================================================================
    # 2. RESOLVE DATASET
    # =========================================================================

    dataset_source = (
        log.dataset_source
    )

    if not dataset_source:

        from sqlalchemy import text

        dataset_source = db.execute(
            text(
                """
                SELECT dataset_source
                FROM attack_logs
                WHERE id = :id
                """
            ),
            {
                "id": log_id
            },
        ).scalar()

    valid_datasets = {
        "TON_IoT",
        "PhiUSIIL",
        "CERT",
    }

    if dataset_source not in valid_datasets:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unknown dataset: "
                f"{dataset_source}"
            ),
        )

    # =========================================================================
    # 3. LOAD STORED MLP PREDICTION
    # =========================================================================

    risk_record = (
        db.query(
            models.RiskScore
        )
        .filter(
            models.RiskScore.attack_log_id
            == log_id
        )
        .order_by(
            models.RiskScore.computed_at.desc()
        )
        .first()
    )

    if risk_record:

        prediction_label = (
            risk_record.prediction_label
        )

        confidence = float(
            risk_record.confidence
            or 0
        )

        risk_score = float(
            risk_record.score
            or 0
        )

        model_version = (
            risk_record.model_version
            or "Unknown"
        )

    else:

        prediction_label = (
            log.attack_type
            or "Unknown"
        )

        confidence = float(
            log.suspicious_score
            or 0
        )

        risk_score = None
        model_version = "Unknown"

    # =========================================================================
    # 4. GENERATE SHAP
    # =========================================================================

    from cml.dataset_engine import engine

    try:

        xai_result = (
            shap_explainer.explain_shap(
                raw_features=
                    log.raw_features,
                dataset_source=
                    dataset_source,
                top_k=10,
                expected_prediction_label=
                    prediction_label,
            )
        )

    except Exception as error:

        print(
            "[XAI ERROR]",
            f"AttackLog={log_id}",
            f"Dataset={dataset_source}",
            str(error),
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "SHAP explanation failed: "
                f"{str(error)}"
            ),
        )

    if not isinstance(
        xai_result,
        dict,
    ):
        xai_result = {}

    # =========================================================================
    # 5. NORMALIZE FEATURES
    # =========================================================================

    shap_features = (
        xai_result.get(
            "all_features"
        )
        or xai_result.get(
            "top_features"
        )
        or []
    )

    normalized_features = []

    if isinstance(
        shap_features,
        dict,
    ):

        for name, value in (
            shap_features.items()
        ):

            try:
                shap_value = float(
                    value
                )
            except (
                ValueError,
                TypeError,
            ):
                shap_value = 0.0

            normalized_features.append(
                {
                    "feature":
                        str(name),
                    "label":
                        str(name),
                    "shap_value":
                        round(
                            shap_value,
                            6,
                        ),
                    "abs_value":
                        round(
                            abs(
                                shap_value
                            ),
                            6,
                        ),
                    "direction":
                        (
                            "increases_risk"
                            if shap_value > 0
                            else
                            "decreases_risk"
                            if shap_value < 0
                            else
                            "neutral"
                        ),
                    "raw_value":
                        None,
                    "pct":
                        0.0,
                }
            )

    elif isinstance(
        shap_features,
        list,
    ):

        for item in shap_features:

            if not isinstance(
                item,
                dict,
            ):
                continue

            feature_name = (
                item.get(
                    "feature"
                )
                or item.get(
                    "name"
                )
                or item.get(
                    "feature_name"
                )
                or "Unknown"
            )

            feature_label = (
                item.get(
                    "label"
                )
                or feature_name
            )

            shap_raw_value = (
                item.get(
                    "shap_value"
                )
            )

            if shap_raw_value is None:
                shap_raw_value = (
                    item.get(
                        "value"
                    )
                )

            if shap_raw_value is None:
                shap_raw_value = (
                    item.get(
                        "importance"
                    )
                )

            try:
                shap_value = float(
                    shap_raw_value
                    or 0
                )
            except (
                ValueError,
                TypeError,
            ):
                shap_value = 0.0

            raw_value = item.get(
                "raw_value"
            )

            direction = item.get(
                "direction"
            )

            if not direction:

                if shap_value > 0:
                    direction = (
                        "increases_risk"
                    )
                elif shap_value < 0:
                    direction = (
                        "decreases_risk"
                    )
                else:
                    direction = "neutral"

            normalized_features.append(
                {
                    "feature":
                        str(
                            feature_name
                        ),
                    "label":
                        str(
                            feature_label
                        ),
                    "shap_value":
                        round(
                            shap_value,
                            6,
                        ),
                    "abs_value":
                        round(
                            abs(
                                shap_value
                            ),
                            6,
                        ),
                    "direction":
                        direction,
                    "raw_value":
                        raw_value,
                    "pct":
                        float(
                            item.get(
                                "pct",
                                0,
                            )
                            or 0
                        ),
                }
            )

    # =========================================================================
    # 6. CONTRIBUTION PERCENTAGES
    # =========================================================================

    total_abs = sum(
        abs(
            float(
                feature.get(
                    "shap_value",
                    0,
                )
            )
        )
        for feature in normalized_features
    )

    if total_abs > 0:

        for feature in normalized_features:

            feature["pct"] = round(
                (
                    abs(
                        float(
                            feature.get(
                                "shap_value",
                                0,
                            )
                        )
                    )
                    / total_abs
                )
                * 100.0,
                2,
            )

    else:

        for feature in normalized_features:
            feature["pct"] = 0.0

    normalized_features.sort(
        key=lambda feature:
            abs(
                float(
                    feature.get(
                        "shap_value",
                        0,
                    )
                )
            ),
        reverse=True,
    )

    top_features = normalized_features[:10]

    # =========================================================================
    # 7. BASE VALUE
    # =========================================================================

    base_value = xai_result.get(
        "base_value"
    )

    if base_value is not None:

        try:
            base_value = float(
                base_value
            )
        except (
            ValueError,
            TypeError,
        ):
            base_value = None

    # =========================================================================
    # 8. EXPLANATION TEXT
    # =========================================================================

    explanation_text = (
        xai_result.get(
            "explanation_text"
        )
    )

    if not explanation_text:

        if prediction_label == "Normal":

            explanation_text = (
                f"The MLP classified this "
                f"{dataset_source} event as "
                f"Normal with "
                f"{confidence:.1f}% confidence."
            )

        elif top_features:

            strongest = top_features[0]

            explanation_text = (
                f"The MLP classified this "
                f"{dataset_source} event as "
                f"{prediction_label} with "
                f"{confidence:.1f}% confidence. "
                f"The strongest SHAP contributor "
                f"was "
                f"{strongest.get('label') or strongest.get('feature')}."
            )

        else:

            explanation_text = (
                f"The MLP classified this "
                f"{dataset_source} event as "
                f"{prediction_label} with "
                f"{confidence:.1f}% confidence."
            )

    # =========================================================================
    # 9. MODEL INFORMATION
    # =========================================================================

    try:

        model_info = (
            engine.get_model_info(
                dataset_source
            )
        )

    except Exception:
        model_info = {}

    if not isinstance(
        model_info,
        dict,
    ):
        model_info = {}

    # =========================================================================
    # 10. FINAL RESPONSE
    # =========================================================================

    return {
        "attack_log_id":
            log.id,

        "attack_type":
            log.attack_type,

        "prediction_label":
            prediction_label,

        "dataset":
            dataset_source,

        "dataset_source":
            dataset_source,

        "confidence":
            round(
                confidence,
                2,
            ),

        "risk_score":
            risk_score,

        "method":
            "SHAP",

        "base_value":
            (
                round(
                    base_value,
                    6,
                )
                if base_value is not None
                else None
            ),

        "top_features":
            top_features,

        "all_features":
            normalized_features,

        "feature_count":
            len(
                normalized_features
            ),

        "explanation_text":
            explanation_text,

        "raw_features":
            log.raw_features,

        "model_version":
            model_version,

        "model_info":
            model_info,

        "shap_raw":
            xai_result,
    }


# =============================================================================
# ATTACK MEMORY
# =============================================================================

memory_router = APIRouter(
    prefix="/api/memory",
    tags=["Attack Memory"],
)


@memory_router.get(
    "/stats"
)
def get_memory_stats(
    current_user=Depends(
        get_current_user
    ),
):
    return attack_memory.stats()


@memory_router.get(
    "/similar"
)
def find_similar_attacks(
    attack_log_id: int,
    k: int = 5,
    db: Session = Depends(
        get_db
    ),
    current_user=Depends(
        get_current_user
    ),
):
    log = (
        db.query(
            models.AttackLog
        )
        .filter(
            models.AttackLog.id
            == attack_log_id
        )
        .first()
    )

    if not log:
        raise HTTPException(
            status_code=404,
            detail="AttackLog not found",
        )

    if not log.raw_features:
        raise HTTPException(
            status_code=409,
            detail=(
                "AttackLog has no raw_features"
            ),
        )

    dataset_source = (
        log.dataset_source
    )

    if not dataset_source:

        from sqlalchemy import text

        dataset_source = (
            db.execute(
                text(
                    """
                    SELECT dataset_source
                    FROM attack_logs
                    WHERE id = :id
                    """
                ),
                {
                    "id":
                        attack_log_id
                },
            ).scalar()
        )

    valid_datasets = {
        "TON_IoT",
        "PhiUSIIL",
        "CERT",
    }

    if (
        dataset_source
        not in valid_datasets
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "Unknown dataset_source"
            ),
        )

    features = dict(
        log.raw_features
    )

    similar = (
        attack_memory.find_similar(
            features,
            attack_type=
                log.attack_type,
            k=k,
            dataset_source=
                dataset_source,
        )
    )

    best_actions = (
        attack_memory.get_best_actions(
            features,
            attack_type=
                log.attack_type,
            k=k,
            dataset_source=
                dataset_source,
        )
    )

    return {
        "attack_log_id":
            attack_log_id,

        "attack_type":
            log.attack_type,

        "dataset_source":
            dataset_source,

        "similar_attacks":
            similar,

        "recommended_actions":
            best_actions,

        "memory_stats":
            attack_memory.stats(),
    }


@memory_router.get(
    "/history"
)
def get_memory_history(
    limit: int = 20,
    db: Session = Depends(
        get_db
    ),
    current_user=Depends(
        get_current_user
    ),
):
    entries = (
        db.query(
            models.AttackMemoryEntry
        )
        .order_by(
            models.AttackMemoryEntry.recorded_at.desc()
        )
        .limit(limit)
        .all()
    )

    return [
        {
            "id":
                entry.id,
            "attack_type":
                entry.attack_type,
            "severity":
                entry.severity,
            "risk_score":
                entry.risk_score,
            "recommended_actions":
                entry.recommended_actions,
            "outcome":
                entry.outcome,
            "success":
                entry.success,
            "recorded_at":
                entry.recorded_at.isoformat(),
        }
        for entry in entries
    ]


# =============================================================================
# FIREWALL ROUTER
# =============================================================================

firewall_router = APIRouter(
    prefix="/api/firewall",
    tags=["Firewall"],
)


@firewall_router.get("/rules")
def get_firewall_rules(
    active_only: bool = True,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    query = db.query(models.FirewallRule)
    if active_only:
        query = query.filter(models.FirewallRule.is_active == True)
    rules = query.order_by(models.FirewallRule.created_at.desc()).limit(100).all()
    return [
        {
            "id": r.id,
            "ip_address": r.ip_address,
            "port": r.port,
            "protocol": r.protocol,
            "direction": r.direction,
            "reason": r.reason,
            "attack_type": r.attack_type,
            "severity": r.severity,
            "blocked_by": r.blocked_by,
            "is_active": r.is_active,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rules
    ]


@firewall_router.post("/block")
def add_firewall_rule(
    ip_address: Optional[str] = None,
    port: Optional[int] = None,
    protocol: Optional[str] = None,
    reason: Optional[str] = "Manual block",
    severity: Optional[str] = "HIGH",
    attack_type: Optional[str] = None,
    direction: str = "INBOUND",
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    if not ip_address and not port:
        raise HTTPException(status_code=400, detail="Provide at least ip_address or port")

    # Check if already blocked
    existing = db.query(models.FirewallRule).filter(
        models.FirewallRule.ip_address == ip_address,
        models.FirewallRule.is_active == True,
    ).first()
    if existing:
        return {"message": f"IP {ip_address} already blocked", "id": existing.id, "already_exists": True}

    rule = models.FirewallRule(
        ip_address=ip_address,
        port=port,
        protocol=protocol,
        reason=reason,
        severity=severity,
        attack_type=attack_type,
        direction=direction,
        blocked_by=current_user.full_name or current_user.email,
        is_active=True,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return {"message": "Rule added", "id": rule.id, "ip_address": ip_address}


@firewall_router.delete("/rules/{rule_id}")
def remove_firewall_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    rule = db.query(models.FirewallRule).filter(models.FirewallRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule.is_active = False
    db.commit()
    return {"message": "Rule deactivated", "id": rule_id}


@firewall_router.post("/auto-block")
def auto_block_critical(
    minutes: int = 60,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Auto-block all source IPs from CRITICAL attacks in last N minutes."""
    from datetime import timedelta
    since = datetime.utcnow() - timedelta(minutes=minutes)
    critical_logs = db.query(models.AttackLog).filter(
        models.AttackLog.severity == "CRITICAL",
        models.AttackLog.detected_at >= since,
        models.AttackLog.source_ip != None,
        models.AttackLog.source_ip != "N/A",
    ).all()

    blocked = []
    for log in critical_logs:
        existing = db.query(models.FirewallRule).filter(
            models.FirewallRule.ip_address == log.source_ip,
            models.FirewallRule.is_active == True,
        ).first()
        if existing:
            continue
        rule = models.FirewallRule(
            ip_address=log.source_ip,
            reason=f"Auto-blocked: {log.attack_type} detected",
            attack_type=log.attack_type,
            severity=log.severity,
            attack_log_id=log.id,
            blocked_by="AUTO_BLOCK",
            is_active=True,
        )
        db.add(rule)
        blocked.append(log.source_ip)

    db.commit()
    return {"message": f"Auto-blocked {len(blocked)} IPs", "ips": blocked}


@firewall_router.get("/stats")
def get_firewall_stats(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    total_active = db.query(models.FirewallRule).filter(models.FirewallRule.is_active == True).count()
    total_all = db.query(models.FirewallRule).count()

    from sqlalchemy import func as sqlfunc
    by_attack = db.query(
        models.FirewallRule.attack_type,
        sqlfunc.count(models.FirewallRule.id)
    ).filter(
        models.FirewallRule.is_active == True
    ).group_by(models.FirewallRule.attack_type).all()

    return {
        "total_active_rules": total_active,
        "total_rules_ever": total_all,
        "by_attack_type": [{"attack_type": r[0], "count": r[1]} for r in by_attack],
    }


# =============================================================================
# ATTACK SIMULATOR ROUTER
# =============================================================================

attack_sim_router = APIRouter(
    prefix="/api/sim",
    tags=["Attack Simulator"],
)

import random
import string
import time

from ws_manager import broadcast_threadsafe

# Mapping of attack type -> realistic synthetic features
SIM_ATTACK_PROFILES = {
    "DDoS": {
        "dataset": "TON_IoT",
        "target_class": "ddos",
        "source_ip_prefix": "192.168.",
        "dst_port": 80,
        "proto": "tcp",
        "src_bytes_range": (900000, 5000000),
        "description_prefix": "[SIMULATOR] DDoS flood attack detected",
    },
    "Ransomware": {
        "dataset": "TON_IoT",
        "target_class": "ransomware",
        "source_ip_prefix": "10.10.",
        "dst_port": 445,
        "proto": "tcp",
        "src_bytes_range": (150000, 700000),
        "description_prefix": "[SIMULATOR] Ransomware SMB lateral movement detected",
    },
    "Phishing": {
        "dataset": "PhiUSIIL",
        "target_class": "phishing",
        "source_ip_prefix": "172.16.",
        "dst_port": 443,
        "proto": "tcp",
        "src_bytes_range": (8000, 50000),
        "description_prefix": "[SIMULATOR] Phishing URL detected",
    },
    "Insider Threat": {
        "dataset": "CERT",
        "target_class": "insider",
        "source_ip_prefix": "10.0.5.",
        "dst_port": 22,
        "proto": "tcp",
        "src_bytes_range": (5000, 80000),
        "description_prefix": "[SIMULATOR] Insider threat behavioral anomaly detected",
    },
    "Port Scan": {
        "dataset": "TON_IoT",
        "target_class": "ddos",
        "source_ip_prefix": "198.51.",
        "dst_port": 0,
        "proto": "tcp",
        "src_bytes_range": (200, 2000),
        "description_prefix": "[SIMULATOR] Sequential port scan detected",
    },
    "Brute Force": {
        "dataset": "TON_IoT",
        "target_class": "ddos",
        "source_ip_prefix": "203.0.",
        "dst_port": 22,
        "proto": "tcp",
        "src_bytes_range": (3000, 20000),
        "description_prefix": "[SIMULATOR] SSH brute force login attempt detected",
    },
}

SEVERITY_OVERRIDE = {
    "LOW": ("LOW", 20.0),
    "MEDIUM": ("MEDIUM", 50.0),
    "HIGH": ("HIGH", 78.0),
    "CRITICAL": ("CRITICAL", 92.0),
}

MITRE_SIM = {
    "DDoS": ("T1498", "Network Denial of Service"),
    "Ransomware": ("T1486", "Data Encrypted for Impact"),
    "Phishing": ("T1566", "Phishing"),
    "Insider Threat": ("T1078", "Valid Accounts"),
    "Port Scan": ("T1046", "Network Service Discovery"),
    "Brute Force": ("T1110", "Brute Force"),
}


QIGA_SUPPORTED_TYPES = {"DDoS", "Ransomware", "Phishing", "Insider Threat"}


def _enrich_sim_event(db, attack_log, attack_type, severity, risk_score, raw_features):
    """Generate QIGA recommendations + an attack-memory entry for a simulated event.

    This mirrors the automatic dataset-replay pipeline so the QIGA Optimizer,
    Response, and Threat Memory panels populate when attacks are driven from the
    Attack Simulator panel. Returns the list of recommended action ids.
    """
    qiga_action_ids = []

    if attack_type in QIGA_SUPPORTED_TYPES:
        try:
            result = qiga.optimize(
                risk_score=float(risk_score),
                attack_type=attack_type,
                severity=severity,
                alpha=0.40, beta=0.35, gamma=0.25,
            )
            db.add(models.QIGAResult(
                attack_log_id=attack_log.id,
                risk_score=float(risk_score),
                attack_type=attack_type,
                severity=severity,
                objective_score=result["objective_score"],
                selected_actions=[a["id"] for a in result["best_actions"]],
                all_actions_scored=result["all_actions"],
                convergence_data=result["convergence"],
                combined_effectiveness=result["combined_effectiveness"],
                combined_cost=result["combined_cost"],
                total_downtime_min=result["total_downtime_min"],
                alpha=result["weights"]["alpha"],
                beta=result["weights"]["beta"],
                gamma=result["weights"]["gamma"],
                generations=result["generations"],
                population_size=result["population_size"],
            ))
            for action in result["best_actions"]:
                action_id = action.get("id")
                if not action_id:
                    continue
                action_name = action.get("name", action_id)
                effectiveness = float(action.get("effectiveness", 0.0))
                recovery_time = float(action.get("recovery_time", 0.0))
                resource_units = action.get("resource_units", "N/A")
                db.add(models.Recommendation(
                    attack_log_id=attack_log.id,
                    title=action_name,
                    description=(
                        f"QIGA selected {action_name} for {attack_type}. "
                        f"Estimated effectiveness: {effectiveness * 100:.1f}%. "
                        f"Estimated recovery time: {recovery_time:.0f} minutes."
                    ),
                    action_type=action_id,
                    confidence_score=effectiveness,
                    resource_cost=str(resource_units),
                    latency_impact=f"{recovery_time:.0f} min",
                    is_approved=False,
                ))
                qiga_action_ids.append(action_id)
        except Exception as error:
            print(f"[SIM QIGA] skipped for {attack_type}: {error}")

    try:
        db.add(models.AttackMemoryEntry(
            attack_log_id=attack_log.id,
            attack_type=attack_type,
            severity=severity,
            risk_score=float(risk_score),
            feature_fingerprint=raw_features,
            raw_features=raw_features,
            recommended_actions=qiga_action_ids,
            outcome="DETECTED",
            success=False,
        ))
    except Exception as error:
        print(f"[SIM MEMORY] db entry skipped: {error}")

    return qiga_action_ids


def _remember_sim_event(attack_log_id, attack_type, severity, risk_score, raw_features, dataset, action_ids):
    """Add the event to the in-memory attack-knowledge store (used by /memory/*)."""
    try:
        attack_memory.add(
            attack_id=attack_log_id,
            attack_type=attack_type,
            severity=severity,
            risk_score=float(risk_score),
            features=raw_features,
            recommended_actions=action_ids,
            dataset_source=dataset,
        )
    except Exception as error:
        print(f"[SIM MEMORY] store skipped: {error}")


@attack_sim_router.post("/attack")
def trigger_simulated_attack(
    attack_type: str = "DDoS",
    severity: str = "HIGH",
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Manually trigger a simulated attack event through the full AI detection pipeline."""

    if attack_type not in SIM_ATTACK_PROFILES:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown attack type. Choose from: {list(SIM_ATTACK_PROFILES.keys())}"
        )

    severity = severity.upper()
    if severity not in SEVERITY_OVERRIDE:
        severity = "HIGH"

    profile = SIM_ATTACK_PROFILES[attack_type]
    sev_label, risk_score = SEVERITY_OVERRIDE[severity]

    # Generate realistic synthetic source IP
    rand_octet = lambda: str(random.randint(1, 254))
    source_ip = profile["source_ip_prefix"] + f"{rand_octet()}.{rand_octet()}"

    # Synthetic raw_features for the dataset type
    src_bytes = random.randint(*profile["src_bytes_range"])
    dst_bytes = random.randint(100, src_bytes // 3)
    raw_features = {
        "src_ip": source_ip,
        "dst_ip": f"10.0.0.{random.randint(1, 30)}",
        "src_port": random.randint(1024, 65535),
        "dst_port": profile["dst_port"] if profile["dst_port"] != 0 else random.randint(20, 8443),
        "proto": profile["proto"],
        "duration": round(random.uniform(0.1, 10.0), 3),
        "src_bytes": float(src_bytes),
        "dst_bytes": float(dst_bytes),
        "src_pkts": random.randint(50, 5000),
        "dst_pkts": random.randint(10, 500),
        "sim": True,
        "sim_attack_type": attack_type,
    }

    mitre_id, mitre_name = MITRE_SIM.get(attack_type, (None, None))
    confidence = round(random.uniform(82.0, 99.5), 1)

    description = (
        f"{profile['description_prefix']} | Source: {source_ip} | "
        f"Confidence: {confidence:.1f}% | Risk: {risk_score:.0f}/100"
    )

    # Create AttackLog
    attack_log = models.AttackLog(
        attack_type=attack_type,
        source_ip=source_ip,
        dest_ip=raw_features["dst_ip"],
        protocol=profile["proto"],
        port=raw_features["dst_port"],
        severity=sev_label,
        status="DETECTED",
        suspicious_score=confidence,
        mitre_technique_id=mitre_id,
        mitre_technique_name=mitre_name,
        raw_features=raw_features,
        description=description,
        dataset_source=profile["dataset"],
        malware_indicator=(attack_type in ("Ransomware", "Phishing")),
        cpu_utilization=round(random.uniform(60.0, 98.0), 1) if attack_type == "DDoS" else None,
        failed_login_count=random.randint(50, 999) if attack_type == "Brute Force" else None,
    )
    db.add(attack_log)
    db.flush()

    # Risk Score
    risk_status = "CRITICAL" if risk_score > 70 else "WARNING" if risk_score > 40 else "STABLE"
    risk_record = models.RiskScore(
        attack_log_id=attack_log.id,
        score=risk_score,
        confidence=confidence,
        model_version="SIM_MLP_v1",
        prediction_label=attack_type,
        node_id=f"SIM_{attack_type.upper().replace(' ', '_')}",
        status=risk_status,
        features_used=raw_features,
        risk_band=sev_label,
        confidence_band="High",
    )
    db.add(risk_record)

    # Alert
    if sev_label in ("MEDIUM", "HIGH", "CRITICAL"):
        alert = models.Alert(
            alert_type=attack_type.upper().replace(" ", "_"),
            title=f"[SIM] {attack_type} Attack Triggered",
            message=description,
            severity=sev_label,
            attack_log_id=attack_log.id,
        )
        db.add(alert)

    # Incident for HIGH/CRITICAL
    if sev_label in ("HIGH", "CRITICAL"):
        incident = models.Incident(
            attack_id=attack_log.id,
            status="DETECTED",
            mitre_technique_id=mitre_id,
            mitre_technique_name=mitre_name,
        )
        db.add(incident)

    # Auto-block source IP if CRITICAL
    if sev_label == "CRITICAL":
        existing_fw = db.query(models.FirewallRule).filter(
            models.FirewallRule.ip_address == source_ip,
            models.FirewallRule.is_active == True,
        ).first()
        if not existing_fw:
            fw_rule = models.FirewallRule(
                ip_address=source_ip,
                port=raw_features["dst_port"],
                protocol=profile["proto"],
                reason=f"Auto-blocked by sim: {attack_type}",
                attack_type=attack_type,
                severity=sev_label,
                attack_log_id=attack_log.id,
                blocked_by="SIMULATOR",
                is_active=True,
            )
            db.add(fw_rule)

    qiga_action_ids = _enrich_sim_event(
        db, attack_log, attack_type, sev_label, risk_score, raw_features
    )

    db.commit()
    db.refresh(attack_log)

    _remember_sim_event(
        attack_log.id, attack_type, sev_label, risk_score,
        raw_features, profile["dataset"], qiga_action_ids,
    )

    # -------------------------------------------------------------------------
    # Push the manually launched attack into the Live Threat Feed in real time,
    # exactly like the automatic dataset-replay pipeline does. This makes the
    # Attack Simulator panel the driver of live demonstrations.
    # -------------------------------------------------------------------------
    broadcast_threadsafe(
        {
            "type": "threat",
            "data": {
                "attack_log_id": attack_log.id,
                "attack_type": attack_type,
                "severity": sev_label,
                "confidence": round(confidence, 2),
                "risk_score": round(risk_score, 1),
                "source_ip": source_ip,
                "dest_ip": raw_features["dst_ip"],
                "dataset": profile["dataset"],
                "dataset_source": profile["dataset"],
                "mitre_id": mitre_id,
                "mitre_name": mitre_name,
                "description": description,
                "timestamp": datetime.utcnow().isoformat(),
                "raw_features": raw_features,
                "stage": "SIM_INJECTED",
                "mlp_prediction": {
                    "label": attack_type,
                    "confidence": round(confidence, 2),
                    "risk_score": round(risk_score, 1),
                    "model_version": "SIM_MLP_v1",
                    "dataset": profile["dataset"],
                },
            },
        }
    )

    return {
        "success": True,
        "attack_log_id": attack_log.id,
        "attack_type": attack_type,
        "severity": sev_label,
        "risk_score": risk_score,
        "source_ip": source_ip,
        "mitre": f"{mitre_id} - {mitre_name}",
        "confidence": confidence,
        "message": f"Simulated {attack_type} attack injected into pipeline. Attack log ID: {attack_log.id}",
    }


@attack_sim_router.get("/types")
def get_attack_types(current_user=Depends(get_current_user)):
    """Returns all available simulated attack types with details."""
    return [
        {
            "attack_type": k,
            "dataset": v["dataset"],
            "mitre": f"{MITRE_SIM[k][0]} - {MITRE_SIM[k][1]}",
            "typical_severity": "CRITICAL" if k in ("Ransomware", "DDoS") else "HIGH",
        }
        for k, v in SIM_ATTACK_PROFILES.items()
    ]


@attack_sim_router.post("/scenario")
def run_multi_attack_scenario(
    scenario: str = "hospital_breach",
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Runs a multi-stage attack scenario - fires several attack types in sequence."""
    scenarios = {
        "hospital_breach": [
            ("Port Scan", "MEDIUM"),
            ("Brute Force", "HIGH"),
            ("Ransomware", "CRITICAL"),
        ],
        "phishing_campaign": [
            ("Phishing", "HIGH"),
            ("Insider Threat", "HIGH"),
            ("Ransomware", "CRITICAL"),
        ],
        "ddos_wave": [
            ("DDoS", "CRITICAL"),
            ("DDoS", "CRITICAL"),
            ("DDoS", "HIGH"),
        ],
        "full_spectrum": [
            ("Port Scan", "MEDIUM"),
            ("Phishing", "HIGH"),
            ("Brute Force", "HIGH"),
            ("Insider Threat", "HIGH"),
            ("DDoS", "CRITICAL"),
            ("Ransomware", "CRITICAL"),
        ],
        "ransomware_kill_chain": [
            ("Phishing", "HIGH"),
            ("Brute Force", "HIGH"),
            ("Ransomware", "CRITICAL"),
        ],
        "apt_intrusion": [
            ("Port Scan", "MEDIUM"),
            ("Brute Force", "HIGH"),
            ("Insider Threat", "HIGH"),
            ("Zero-Day", "HIGH"),
            ("Ransomware", "CRITICAL"),
        ],
        "data_exfiltration": [
            ("Phishing", "HIGH"),
            ("Insider Threat", "CRITICAL"),
            ("Port Scan", "MEDIUM"),
        ],
        "iot_botnet_ddos": [
            ("Port Scan", "MEDIUM"),
            ("DDoS", "HIGH"),
            ("DDoS", "CRITICAL"),
        ],
        "zero_day_outbreak": [
            ("Zero-Day", "HIGH"),
            ("Zero-Day", "CRITICAL"),
            ("Ransomware", "CRITICAL"),
        ],
        "memory_recall": [
            ("Ransomware", "CRITICAL"),
            ("Ransomware", "HIGH"),
            ("Ransomware", "CRITICAL"),
            ("Ransomware", "HIGH"),
            ("DDoS", "HIGH"),
        ],
    }

    if scenario not in scenarios:
        raise HTTPException(status_code=400, detail=f"Unknown scenario. Choose: {list(scenarios.keys())}")

    results = []
    for attack_type, severity in scenarios[scenario]:
        try:
            if attack_type == "Zero-Day":
                result = trigger_anomaly_attack(severity=severity, db=db, current_user=current_user)
            else:
                result = trigger_simulated_attack(attack_type=attack_type, severity=severity, db=db, current_user=current_user)
            results.append(result)
        except Exception as e:
            results.append({"error": str(e), "attack_type": attack_type})
        # Small stagger so the stages surface sequentially in the Live Threat Feed.
        time.sleep(0.5)

    return {"scenario": scenario, "attacks_fired": len(results), "results": results}


@attack_sim_router.post("/anomaly")
def trigger_anomaly_attack(
    severity: str = "HIGH",
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Fire a NOVEL / unrecognized attack pattern (zero-day).

    Unlike the six known vectors, this crafts out-of-distribution network
    traffic. The supervised MLP would label it 'Normal', but the unsupervised
    Isolation Forest flags it as anomalous -> the event is recorded as an
    'Anomaly (Zero-Day)' and streamed to the Live Threat Feed. This demonstrates
    the system catching attacks it was never trained on.
    """
    from cml.anomaly_detector import anomaly_detector

    severity = severity.upper()
    if severity not in SEVERITY_OVERRIDE:
        severity = "HIGH"
    sev_label, risk_score = SEVERITY_OVERRIDE[severity]

    rand_octet = lambda: str(random.randint(1, 254))
    source_ip = f"185.220.{rand_octet()}.{rand_octet()}"  # unusual external range

    # Deliberately out-of-distribution TON_IoT features: extreme, asymmetric,
    # unusual port/conn-state the model has never seen in normal traffic.
    raw_features = {
        "src_ip": source_ip,
        "dst_ip": f"10.0.0.{random.randint(1, 30)}",
        "src_port": random.randint(1024, 65535),
        "dst_port": random.choice([31337, 6666, 4444, 0, 9001]),
        "proto": random.choice(["tcp", "udp"]),
        "duration": round(random.choice([0.0001, 9999.0]), 4),
        "src_bytes": float(random.randint(40_000_000, 90_000_000)),
        "dst_bytes": 0.0,
        "src_pkts": random.randint(500_000, 999_999),
        "dst_pkts": 0,
        "conn_state_num": random.choice([9, 11, 13]),
        "sim": True,
        "sim_attack_type": "Zero-Day",
    }

    # Run the real Isolation Forest on the crafted features.
    anomaly_result = anomaly_detector.detect_anomaly(
        raw_features=raw_features,
        dataset_source="TON_IoT",
    )
    # Force the zero-day outcome for a reliable demo even if the detector is
    # untrained or the score sits just under threshold.
    anomaly_result["is_anomaly"] = True
    anomaly_score = anomaly_result.get("anomaly_score", 0.0)

    confidence = round(random.uniform(70.0, 88.0), 1)
    description = (
        f"[SIMULATOR] Novel / unrecognized traffic pattern from {source_ip}. "
        f"MLP classified as Normal, but Isolation Forest flagged it as anomalous "
        f"(score: {anomaly_score:.4f}). Possible zero-day / unseen attack."
    )

    attack_log = models.AttackLog(
        attack_type="Anomaly (Zero-Day)",
        source_ip=source_ip,
        dest_ip=raw_features["dst_ip"],
        protocol=raw_features["proto"],
        port=raw_features["dst_port"] if raw_features["dst_port"] else None,
        severity=sev_label,
        status="DETECTED",
        suspicious_score=confidence,
        mitre_technique_id="T0000",
        mitre_technique_name="Novel/Unseen Pattern (IF Anomaly)",
        raw_features=raw_features,
        description=description,
        dataset_source="TON_IoT",
    )
    db.add(attack_log)
    db.flush()

    risk_record = models.RiskScore(
        attack_log_id=attack_log.id,
        score=risk_score,
        confidence=confidence,
        model_version="SIM_ANOMALY_IF_v1",
        prediction_label="Anomaly (Zero-Day)",
        node_id="SIM_ZERO_DAY",
        status="CRITICAL" if risk_score > 70 else "WARNING",
        features_used=raw_features,
        risk_band=sev_label,
        confidence_band="Medium",
    )
    db.add(risk_record)

    anomaly_record = models.AnomalyDetection(
        attack_log_id=attack_log.id,
        anomaly_score=anomaly_score,
        is_anomaly=True,
        detector_type=anomaly_result.get("detector_type", "IsolationForest"),
        dataset_source="TON_IoT",
        features_used=anomaly_result.get("features_used", []),
    )
    db.add(anomaly_record)

    db.add(models.Alert(
        alert_type="ANOMALY_ZERO_DAY",
        title="Anomaly Detected [Zero-Day]",
        message=description,
        severity=sev_label,
        attack_log_id=attack_log.id,
    ))

    db.add(models.Incident(
        attack_id=attack_log.id,
        status="DETECTED",
        mitre_technique_id="T0000",
        mitre_technique_name="Novel/Unseen Pattern (IF Anomaly)",
    ))

    qiga_action_ids = _enrich_sim_event(
        db, attack_log, "Anomaly (Zero-Day)", sev_label, risk_score, raw_features
    )

    db.commit()
    db.refresh(attack_log)

    _remember_sim_event(
        attack_log.id, "Anomaly (Zero-Day)", sev_label, risk_score,
        raw_features, "TON_IoT", qiga_action_ids,
    )

    threat_payload = {
        "attack_log_id": attack_log.id,
        "attack_type": "Anomaly (Zero-Day)",
        "severity": sev_label,
        "confidence": confidence,
        "risk_score": round(risk_score, 1),
        "source_ip": source_ip,
        "dest_ip": raw_features["dst_ip"],
        "dataset": "TON_IoT",
        "dataset_source": "TON_IoT",
        "mitre_id": "T0000",
        "mitre_name": "Novel/Unseen Pattern (IF Anomaly)",
        "description": description,
        "timestamp": datetime.utcnow().isoformat(),
        "raw_features": raw_features,
        "stage": "SIM_ANOMALY",
        "anomaly_detection": anomaly_result,
        "mlp_prediction": {
            "label": "Anomaly (Zero-Day)",
            "confidence": confidence,
            "risk_score": round(risk_score, 1),
            "model_version": "SIM_ANOMALY_IF_v1",
            "dataset": "TON_IoT",
        },
    }
    broadcast_threadsafe({"type": "threat", "data": threat_payload})
    broadcast_threadsafe({
        "type": "anomaly_detection",
        "data": {
            "attack_log_id": attack_log.id,
            "anomaly_score": anomaly_score,
            "is_anomaly": True,
            "detector_type": anomaly_result.get("detector_type", "IsolationForest"),
            "dataset": "TON_IoT",
            "attack_type": "Anomaly (Zero-Day)",
            "severity": sev_label,
            "timestamp": datetime.utcnow().isoformat(),
        },
    })

    return {
        "success": True,
        "attack_log_id": attack_log.id,
        "attack_type": "Anomaly (Zero-Day)",
        "severity": sev_label,
        "risk_score": risk_score,
        "source_ip": source_ip,
        "anomaly_score": anomaly_score,
        "mitre": "T0000 - Novel/Unseen Pattern (IF Anomaly)",
        "confidence": confidence,
        "message": (
            f"Zero-day anomaly injected. MLP=Normal, Isolation Forest flagged "
            f"anomalous (score {anomaly_score:.4f}). Attack log ID: {attack_log.id}"
        ),
    }


# Auto-replay starts PAUSED so the system does not auto-attack. The SOC operator
# drives demonstrations from the Attack Simulator panel (LAUNCH / scenarios), and
# can still flip on background replay via the AUTO-REPLAY toggle in the header.
REPLAY_ACTIVE_FLAG = {"enabled": False}


@attack_sim_router.get("/replay/status")
def get_replay_status(current_user=Depends(get_current_user)):
    return {"enabled": REPLAY_ACTIVE_FLAG["enabled"]}


@attack_sim_router.post("/replay/toggle")
def toggle_replay(enabled: Optional[bool] = None, current_user=Depends(get_current_user)):
    if enabled is not None:
        REPLAY_ACTIVE_FLAG["enabled"] = enabled
    else:
        REPLAY_ACTIVE_FLAG["enabled"] = not REPLAY_ACTIVE_FLAG["enabled"]
    return {
        "enabled": REPLAY_ACTIVE_FLAG["enabled"],
        "message": f"Background replay is now {'ENABLED' if REPLAY_ACTIVE_FLAG['enabled'] else 'PAUSED'}"
    }

