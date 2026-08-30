import asyncio
import os
from datetime import datetime, timedelta

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from config import settings
from database import engine, Base, SessionLocal
import models

from routers.auth import router as auth_router
from routers.api import (
    logs_router,
    alerts_router,
    predict_router,
    rec_router,
    monitor_router,
    admin_router,
    dashboard_router,
    incidents_router,
    assets_router,
    recovery_router,
    optimizer_router,
    xai_router,
    memory_router,
    firewall_router,
    attack_sim_router,
    REPLAY_ACTIVE_FLAG,
)

from cml.qiga_optimizer import qiga
from cml.shap_explainer import explainer as shap_explainer
from cml.anomaly_detector import anomaly_detector

from ws_manager import manager, set_main_loop


# =============================================================================
# CONFIGURATION
# =============================================================================

DATASET_REPLAY_MODE = settings.DATASET_REPLAY_MODE
REPLAY_INTERVAL_SECONDS = settings.REPLAY_INTERVAL_SECONDS
LIVE_CAPTURE_ENABLED = settings.LIVE_CAPTURE_ENABLED
AUTO_RESPONSE_ENABLED = settings.AUTO_RESPONSE_ENABLED
AUTO_RESPONSE_MIN_SEVERITY = settings.AUTO_RESPONSE_MIN_SEVERITY


# =============================================================================
# DATABASE
# =============================================================================

Base.metadata.create_all(bind=engine)


# =============================================================================
# FASTAPI APPLICATION
# =============================================================================

app = FastAPI(
    title="ICDS-H API",
    description=(
        "Intelligent Cyber Defense System for Healthcare "
        "- Research-Grade SOC Platform"
    ),
    version="2.0.0",
)

cors_origins = [origin.strip() for origin in settings.CORS_ORIGINS.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# SECURITY HEADERS
# =============================================================================
# Defense-in-depth response hardening applied to every response.

@app.middleware("http")
async def security_headers_middleware(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Cache-Control"] = "no-store"
    return response


# =============================================================================
# ROUTERS
# =============================================================================

app.include_router(auth_router)
app.include_router(logs_router)
app.include_router(alerts_router)
app.include_router(predict_router)
app.include_router(rec_router)
app.include_router(monitor_router)
app.include_router(admin_router)
app.include_router(dashboard_router)
app.include_router(incidents_router)
app.include_router(assets_router)
app.include_router(recovery_router)
app.include_router(optimizer_router)
app.include_router(xai_router)
app.include_router(memory_router)
app.include_router(firewall_router)
app.include_router(attack_sim_router)


# =============================================================================
# WEBSOCKET MANAGER
# =============================================================================
# The ConnectionManager and shared `manager` instance now live in ws_manager.py
# so synchronous REST endpoints (e.g. the Attack Simulator) can broadcast into
# the same live feed via broadcast_threadsafe(). Imported at the top of file.


# =============================================================================
# QIGA → RECOMMENDATION BRIDGE
# =============================================================================

def create_qiga_recommendations(
    db: Session,
    attack_log,
    risk_score_record,
):
    """
    Run QIGA for one confirmed MLP-detected AttackLog.

    QIGA receives:
        - the SAME attack classification
        - the SAME severity
        - the SAME MLP-derived RiskScore

    QIGA creates Recommendation rows only.

    It does NOT approve or execute the recommendation.
    Approval is handled separately by the admin/analyst endpoint.
    """

    if not attack_log:
        return {
            "qiga_result": None,
            "recommendations": [],
        }

    if attack_log.attack_type == "Normal":
        return {
            "qiga_result": None,
            "recommendations": [],
        }

    supported_types = {
        "DDoS",
        "Ransomware",
        "Phishing",
        "Insider Threat",
    }

    if attack_log.attack_type not in supported_types:
        return {
            "qiga_result": None,
            "recommendations": [],
        }

    # -------------------------------------------------------------------------
    # Avoid duplicate QIGA execution.
    # -------------------------------------------------------------------------

    existing_qiga = (
        db.query(models.QIGAResult)
        .filter(
            models.QIGAResult.attack_log_id
            == attack_log.id
        )
        .first()
    )

    if existing_qiga:

        existing_recommendations = (
            db.query(models.Recommendation)
            .filter(
                models.Recommendation.attack_log_id
                == attack_log.id
            )
            .order_by(
                models.Recommendation.confidence_score.desc()
            )
            .all()
        )

        return {
            "qiga_result": existing_qiga,
            "recommendations": existing_recommendations,
        }

    # -------------------------------------------------------------------------
    # QIGA uses the REAL MLP risk score.
    # -------------------------------------------------------------------------

    result = qiga.optimize(
        risk_score=float(
            risk_score_record.score
        ),
        attack_type=attack_log.attack_type,
        severity=attack_log.severity,
        alpha=0.40,
        beta=0.35,
        gamma=0.25,
    )

    # -------------------------------------------------------------------------
    # Persist QIGA result.
    # -------------------------------------------------------------------------

    qiga_record = models.QIGAResult(
        attack_log_id=attack_log.id,
        risk_score=float(
            risk_score_record.score
        ),
        attack_type=attack_log.attack_type,
        severity=attack_log.severity,
        objective_score=result["objective_score"],
        selected_actions=[
            action["id"]
            for action in result["best_actions"]
        ],
        all_actions_scored=result["all_actions"],
        convergence_data=result["convergence"],
        combined_effectiveness=result[
            "combined_effectiveness"
        ],
        combined_cost=result[
            "combined_cost"
        ],
        total_downtime_min=result[
            "total_downtime_min"
        ],
        alpha=result["weights"]["alpha"],
        beta=result["weights"]["beta"],
        gamma=result["weights"]["gamma"],
        generations=result["generations"],
        population_size=result["population_size"],
    )

    db.add(qiga_record)
    db.flush()

    # -------------------------------------------------------------------------
    # Convert QIGA best actions into Recommendation records.
    # -------------------------------------------------------------------------

    recommendation_records = []

    for action in result["best_actions"]:

        action_id = action.get("id")

        if not action_id:
            continue

        action_name = action.get(
            "name",
            action_id,
        )

        effectiveness = float(
            action.get(
                "effectiveness",
                0.0,
            )
        )

        recovery_time = float(
            action.get(
                "recovery_time",
                0.0,
            )
        )

        resource_units = action.get(
            "resource_units",
            "N/A",
        )

        description = (
            f"QIGA selected {action_name} for "
            f"{attack_log.attack_type}. "
            f"Estimated effectiveness: "
            f"{effectiveness * 100:.1f}%. "
            f"Estimated recovery time: "
            f"{recovery_time:.0f} minutes."
        )

        recommendation = models.Recommendation(
            attack_log_id=attack_log.id,
            title=action_name,
            description=description,
            action_type=action_id,
            confidence_score=effectiveness,
            resource_cost=str(
                resource_units
            ),
            latency_impact=(
                f"{recovery_time:.0f} min"
            ),
            is_approved=False,
        )

        db.add(recommendation)
        recommendation_records.append(
            recommendation
        )

    db.flush()

    return {
        "qiga_result": qiga_record,
        "recommendations": recommendation_records,
    }


# =============================================================================
# SHAP → MLP EXPLANATION BRIDGE
# =============================================================================

def generate_shap_explanation(
    attack_log,
    prediction_label: str,
):
    """
    Explain the SAME event already classified by the MLP.

    MLP:
        decides prediction_label

    SHAP:
        explains the feature contribution behind that prediction

    SHAP does not replace or overwrite the MLP prediction.
    """

    if not attack_log:
        return None

    dataset_source = (
        getattr(
            attack_log,
            "dataset_source",
            None,
        )
        or ""
    )

    valid_datasets = {
        "TON_IoT",
        "PhiUSIIL",
        "CERT",
    }

    if dataset_source not in valid_datasets:
        return None

    if not attack_log.raw_features:
        return None

    try:

        shap_result = (
            shap_explainer.explain_shap(
                raw_features=attack_log.raw_features,
                dataset_source=dataset_source,
                top_k=5,
            )
        )

        shap_label = shap_result.get(
            "prediction_label"
        )

        if (
            shap_label is not None
            and shap_label != prediction_label
        ):
            print(
                "[SHAP WARNING] Prediction mismatch "
                f"for AttackLog {attack_log.id}: "
                f"MLP={prediction_label}, "
                f"SHAP={shap_label}"
            )

        shap_result["mlp_prediction_label"] = (
            prediction_label
        )

        return shap_result

    except Exception as error:

        print(
            f"[SHAP ERROR] AttackLog "
            f"{attack_log.id}: {error}"
        )

        return None


# =============================================================================
# DATASET REPLAY SERVICE
# =============================================================================

async def dataset_replay_service():

    from cml.dataset_engine import engine

    await asyncio.sleep(3)

    # =========================================================================
    # OPTIONAL UNSEEN PHISHING TEST EVENTS
    #
    # Existing unified_dataset.csv replay remains active.
    #
    # If the test CSV exists:
    #
    #     existing replay event
    #              ↓
    #     unseen phishing event
    #              ↓
    #     existing replay event
    #              ↓
    #     unseen phishing event
    #
    # If the test CSV does not exist:
    #     existing replay continues normally.
    # =========================================================================

    unseen_events = []

    try:

        unseen_events = (
            engine.load_unseen_phishing_events(
                filename="realtime_test/unseen_phishing.csv"
            )
        )

        print(
            "[UNSEEN TEST] Loaded "
            f"{len(unseen_events)} events from "
            "dataset/realtime_test/unseen_phishing.csv"
        )

    except FileNotFoundError:

        print(
            "[UNSEEN TEST] Test CSV not found. "
            "Continuing with existing dataset replay only."
        )

    except Exception as error:

        print(
            "[UNSEEN TEST] Failed to load test CSV: "
            f"{error}"
        )

    unseen_index = 0

    # Start by allowing the first available event
    # to come from the unseen CSV.
    use_unseen_event = True

    while True:

        if not REPLAY_ACTIVE_FLAG.get("enabled", True):
            await asyncio.sleep(1)
            continue

        db = None

        try:

            await asyncio.sleep(
                REPLAY_INTERVAL_SECONDS
            )

            db = SessionLocal()

            # =================================================================
            # 1. DATASET EVENT + MLP PREDICTION
            # =================================================================

            if unseen_events and use_unseen_event:

                event = unseen_events[
                    unseen_index
                ]

                unseen_index = (
                    unseen_index + 1
                ) % len(unseen_events)

                use_unseen_event = False

                print(
                    "[UNSEEN TEST] Processing "
                    f"event {unseen_index or len(unseen_events)}"
                )

            else:

                event = engine.next_event()

                use_unseen_event = True

            prediction_label = (
                event["prediction_label"]
            )

            confidence = float(
                event["confidence"]
            )

            risk_score = float(
                event["risk_score"]
            )

            severity = event["severity"]

            dataset = event["dataset"]

            raw_features = (
                event["raw_features"]
            )

            model_version = (
                event["model_version"]
            )

            # =================================================================
            # 2. CREATE CENTRAL ATTACK LOG
            # =================================================================

            dst_port = raw_features.get(
                "dst_port"
            )

            try:

                port_value = (
                    int(
                        float(
                            dst_port
                        )
                    )
                    if (
                        dst_port is not None
                        and str(dst_port)
                        .replace(".", "")
                        .isdigit()
                    )
                    else None
                )

            except Exception:

                port_value = None

            attack_log = models.AttackLog(
                attack_type=prediction_label,

                source_ip=str(
                    raw_features.get(
                        "src_ip",
                        "N/A",
                    )
                ),

                dest_ip=str(
                    raw_features.get(
                        "dst_ip",
                        "N/A",
                    )
                ),

                protocol=str(
                    raw_features.get(
                        "proto",
                        "N/A",
                    )
                ),

                port=port_value,

                severity=severity,

                status="DETECTED",

                suspicious_score=confidence,

                mitre_technique_id=(
                    event.get(
                        "mitre_technique_id"
                    )
                ),

                mitre_technique_name=(
                    event.get(
                        "mitre_technique_name"
                    )
                ),

                raw_features=raw_features,

                description=event[
                    "description"
                ],

                dataset_source=dataset,
            )

            db.add(attack_log)
            db.flush()

            attack_log_id = attack_log.id

            # =================================================================
            # 3. CREATE MLP RISK SCORE
            # =================================================================

            risk_status = (
                "CRITICAL"
                if risk_score > 70
                else "WARNING"
                if risk_score > 40
                else "STABLE"
            )

            risk_record = models.RiskScore(
                attack_log_id=attack_log_id,

                score=risk_score,

                confidence=confidence,

                model_version=model_version,

                prediction_label=prediction_label,

                node_id=(
                    f"DATASET_{dataset}"
                ),

                status=risk_status,

                features_used=raw_features,
            )

            db.add(risk_record)

            # =================================================================
            # 4. ATTACK DECISION
            # =================================================================

            is_attack = (
                prediction_label
                != "Normal"
            )

            # =================================================================
            # 5. ALERT
            # =================================================================

            if (
                is_attack
                and severity
                in (
                    "MEDIUM",
                    "HIGH",
                    "CRITICAL",
                )
            ):

                alert = models.Alert(
                    alert_type=(
                        prediction_label
                        .upper()
                        .replace(
                            " ",
                            "_",
                        )
                    ),

                    title=(
                        f"{prediction_label} "
                        f"Detected "
                        f"[{dataset}]"
                    ),

                    message=(
                        f"[{dataset}] "
                        f"{event['description']} "
                        f"| Confidence: "
                        f"{confidence:.1f}% "
                        f"| Risk: "
                        f"{risk_score:.0f}"
                    ),

                    severity=severity,

                    attack_log_id=(
                        attack_log_id
                    ),
                )

                db.add(alert)

            # =================================================================
            # 6. INCIDENT
            # =================================================================

            if (
                is_attack
                and severity
                in (
                    "HIGH",
                    "CRITICAL",
                )
            ):

                incident = models.Incident(
                    attack_id=attack_log_id,

                    status="DETECTED",

                    mitre_technique_id=(
                        event.get(
                            "mitre_technique_id"
                        )
                    ),

                    mitre_technique_name=(
                        event.get(
                            "mitre_technique_name"
                        )
                    ),
                )

                db.add(incident)

            # =================================================================
            # 6b. ANOMALY DETECTION (ISOLATION FOREST)
            # =================================================================

            anomaly_result = anomaly_detector.detect_anomaly(
                raw_features=raw_features,
                dataset_source=dataset,
            )

            anomaly_record = models.AnomalyDetection(
                attack_log_id=attack_log_id,
                anomaly_score=anomaly_result["anomaly_score"],
                is_anomaly=anomaly_result["is_anomaly"],
                detector_type=anomaly_result["detector_type"],
                dataset_source=dataset,
                features_used=anomaly_result["features_used"],
            )
            db.add(anomaly_record)

            # If MLP says Normal but Isolation Forest flags anomaly,
            # override to ANOMALY_DETECTED with elevated severity
            if not is_attack and anomaly_result["is_anomaly"]:
                attack_log.attack_type = "Anomaly (Zero-Day)"
                attack_log.severity = "HIGH"
                attack_log.status = "DETECTED"
                attack_log.description = (
                    f"Isolation Forest detected anomalous behavior "
                    f"(score: {anomaly_result['anomaly_score']:.4f}) "
                    f"that the MLP classifier deemed Normal. "
                    f"Possible zero-day or novel attack pattern."
                )
                prediction_label = "Anomaly (Zero-Day)"
                severity = "HIGH"
                is_attack = True

                # Create alert for anomaly
                alert = models.Alert(
                    alert_type="ANOMALY_ZERO_DAY",
                    title=f"Anomaly Detected [{dataset}]",
                    message=(
                        f"Isolation Forest flagged anomalous traffic "
                        f"(score: {anomaly_result['anomaly_score']:.4f}) "
                        f"from {raw_features.get('src_ip', 'N/A')} → "
                        f"{raw_features.get('dst_ip', 'N/A')}. "
                        f"MLP classified as Normal — possible zero-day."
                    ),
                    severity="HIGH",
                    attack_log_id=attack_log_id,
                )
                db.add(alert)

                # Create incident for anomaly
                incident = models.Incident(
                    attack_id=attack_log_id,
                    status="DETECTED",
                    mitre_technique_id="T0000",
                    mitre_technique_name="Novel/Unseen Pattern (IF Anomaly)",
                )
                db.add(incident)

            # =================================================================
            # 7. COMMIT MLP + ANOMALY DETECTION FIRST
            # =================================================================

            db.commit()

            # =================================================================
            # 8. BROADCAST MLP DETECTION FIRST
            # =================================================================

            await manager.broadcast(
                {
                    "type": "threat",

                    "data": {

                        "attack_log_id":
                            attack_log_id,

                        "attack_type":
                            prediction_label,

                        "severity":
                            severity,

                        "confidence":
                            round(
                                confidence,
                                2,
                            ),

                        "risk_score":
                            round(
                                risk_score,
                                1,
                            ),

                       "dataset": (
                                    None
                                    if event.get("input_source") == "UNSEEN_TEST"
                                   else dataset
                                  ),

                        "mitre_id":
                            event.get(
                                "mitre_technique_id"
                            ),

                        "mitre_name":
                            event.get(
                                "mitre_technique_name"
                            ),

                        "model_version":
                            model_version,

                        "description":
                            event[
                                "description"
                            ],

                        "timestamp":
                            datetime.utcnow()
                            .isoformat(),

                        "raw_features":
                            raw_features,

                        "stage":
                            "MLP_DETECTED",

                        "mlp_prediction":
                            {
                                "label":
                                    prediction_label,

                                "confidence":
                                    round(
                                        confidence,
                                        2,
                                    ),

                                "risk_score":
                                    round(
                                        risk_score,
                                        1,
                                    ),

                                "model_version":
                                    model_version,

                                "dataset":
                                    dataset,
                            },

                        "anomaly_detection":
                            anomaly_result,
                    },
                }
            )

            # =================================================================
            # 8b. BROADCAST ANOMALY DETECTION RESULT
            # =================================================================

            if anomaly_result["is_anomaly"]:
                await manager.broadcast(
                    {
                        "type": "anomaly_detection",
                        "data": {
                            "attack_log_id": attack_log_id,
                            "anomaly_score": anomaly_result["anomaly_score"],
                            "is_anomaly": True,
                            "detector_type": anomaly_result["detector_type"],
                            "dataset": dataset,
                            "attack_type": prediction_label,
                            "severity": severity,
                            "timestamp": datetime.utcnow().isoformat(),
                        },
                    }
                )

            # =================================================================
            # 9. SHAP EXPLANATION
            # =================================================================

            shap_result = (
                generate_shap_explanation(
                    attack_log=attack_log,
                    prediction_label=prediction_label,
                )
            )

            # =================================================================
            # 10. BROADCAST SHAP
            # =================================================================

            if shap_result:

                await manager.broadcast(
                    {
                        "type":
                            "shap_explanation",

                        "data": {

                            "attack_log_id":
                                attack_log_id,

                            "attack_type":
                                prediction_label,

                            "dataset":
                                dataset,

                            "prediction_label":
                                shap_result.get(
                                    "prediction_label",
                                    prediction_label,
                                ),

                            "mlp_prediction_label":
                                prediction_label,

                            "method":
                                "SHAP",

                            "status":
                                "COMPLETED",

                            "top_features":
                                shap_result.get(
                                    "top_features",
                                    [],
                                ),

                            "all_features":
                                shap_result.get(
                                    "all_features",
                                    [],
                                ),

                            "explanation_text":
                                shap_result.get(
                                    "explanation_text"
                                ),

                            "base_value":
                                shap_result.get(
                                    "base_value"
                                ),
                        },
                    }
                )

            else:

                await manager.broadcast(
                    {
                        "type":
                            "shap_explanation",

                        "data": {

                            "attack_log_id":
                                attack_log_id,

                            "attack_type":
                                prediction_label,

                            "dataset":
                                dataset,

                            "method":
                                "SHAP",

                            "status":
                                "FAILED",

                            "top_features":
                                [],

                            "all_features":
                                [],
                        },
                    }
                )

            # =================================================================
            # 11. QIGA → RECOMMENDATIONS
            # =================================================================

            qiga_output = {
                "qiga_result": None,
                "recommendations": [],
            }

            if is_attack:

                try:

                    qiga_output = (
                        create_qiga_recommendations(
                            db=db,
                            attack_log=attack_log,
                            risk_score_record=risk_record,
                        )
                    )

                    db.commit()

                except Exception as qiga_error:

                    db.rollback()

                    print(
                        "[QIGA ERROR] "
                        f"AttackLog {attack_log_id}: "
                        f"{qiga_error}"
                    )

                    qiga_output = {
                        "qiga_result": None,
                        "recommendations": [],
                    }

            # =================================================================
            # 12. ATTACK MEMORY
            # =================================================================

            if is_attack:

                recommendations = (
                    qiga_output[
                        "recommendations"
                    ]
                )

                qiga_action_ids = [
                    recommendation.action_type
                    for recommendation
                    in recommendations
                ]

                try:

                    memory_entry = (
                        models.AttackMemoryEntry(
                            attack_log_id=(
                                attack_log_id
                            ),

                            attack_type=(
                                prediction_label
                            ),

                            severity=severity,

                            risk_score=risk_score,

                            feature_fingerprint=(
                                raw_features
                            ),

                            raw_features=(
                                raw_features
                            ),

                            recommended_actions=(
                                qiga_action_ids
                            ),

                            outcome="DETECTED",

                            success=False,
                        )
                    )

                    db.add(memory_entry)

                    from cml.attack_memory import (
                        attack_memory,
                    )

                    attack_memory.add(
                        attack_id=(
                            attack_log_id
                        ),

                        attack_type=(
                            prediction_label
                        ),

                        severity=severity,

                        risk_score=risk_score,

                        features=(
                            raw_features
                        ),

                        recommended_actions=(
                            qiga_action_ids
                        ),
                    )

                    db.commit()

                except Exception as memory_error:

                    db.rollback()

                    print(
                        "[MEMORY ERROR] "
                        f"AttackLog {attack_log_id}: "
                        f"{memory_error}"
                    )

            # =================================================================
            # 13. BROADCAST QIGA / RECOMMENDATIONS
            # =================================================================

            if is_attack:

                qiga_record = (
                    qiga_output[
                        "qiga_result"
                    ]
                )

                recommendations = (
                    qiga_output[
                        "recommendations"
                    ]
                )

                # Determine if auto-response should execute
                severity_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
                min_sev_idx = severity_order.index(AUTO_RESPONSE_MIN_SEVERITY) if AUTO_RESPONSE_MIN_SEVERITY in severity_order else 2
                current_sev_idx = severity_order.index(severity) if severity in severity_order else 0
                should_auto_respond = (
                    AUTO_RESPONSE_ENABLED
                    and current_sev_idx >= min_sev_idx
                    and recommendations
                )

                if qiga_record:

                    # Determine status based on auto-response
                    response_status = "AUTO_APPROVED" if should_auto_respond else "PENDING_APPROVAL"

                    await manager.broadcast(
                        {
                            "type":
                                "qiga_recommendation",

                            "data": {

                                "attack_log_id":
                                    attack_log_id,

                                "attack_type":
                                    prediction_label,

                                "dataset":
                                    dataset,

                                "risk_score":
                                    risk_score,

                                "qiga_id":
                                    qiga_record.id,

                                "objective_score":
                                    qiga_record.objective_score,

                                "status":
                                    response_status,

                                "approval_required":
                                    not should_auto_respond,

                                "selected_actions": [

                                    {
                                        "id":
                                            recommendation.action_type,

                                        "title":
                                            recommendation.title,

                                        "confidence":
                                            round(
                                                (
                                                    recommendation
                                                    .confidence_score
                                                    or 0
                                                )
                                                * 100,
                                                2,
                                            ),

                                        "is_approved":
                                            bool(
                                                recommendation
                                                .is_approved
                                            ),
                                    }

                                    for recommendation
                                    in recommendations
                                ],
                            },
                        }
                    )

            # =================================================================
            # 14. AUTO-RESPONSE EXECUTION
            # =================================================================

            if is_attack and should_auto_respond and recommendations:

                try:
                    # Pick the top recommendation (highest confidence)
                    top_rec = max(
                        recommendations,
                        key=lambda r: r.confidence_score or 0,
                    )

                    valid_auto_actions = {
                        "ISOLATE", "BLOCK", "RESTORE", "RESET", "PATCH",
                    }

                    if top_rec.action_type in valid_auto_actions:

                        # Auto-approve
                        top_rec.is_approved = True
                        top_rec.approved_at = datetime.utcnow()

                        # Create recovery action
                        target_node = (
                            attack_log.dest_ip or "UNKNOWN"
                        )

                        recovery = models.RecoveryAction(
                            recommendation_id=top_rec.id,
                            action_name=top_rec.title,
                            action_type=top_rec.action_type,
                            target_node=str(target_node)[:100],
                            status="IN_PROGRESS",
                            started_at=datetime.utcnow(),
                        )
                        db.add(recovery)

                        # Update attack log status
                        attack_log.status = "CONTAINMENT"

                        # Update incident
                        auto_incident = (
                            db.query(models.Incident)
                            .filter(
                                models.Incident.attack_id
                                == attack_log_id
                            )
                            .first()
                        )
                        if auto_incident:
                            auto_incident.status = "CONTAINMENT"

                        db.commit()
                        db.refresh(recovery)

                        # Simulate recovery completion
                        recovery.status = "COMPLETED"
                        recovery.completed_at = datetime.utcnow()
                        recovery.execution_log = (
                            f"[AUTO-RESPONSE] {top_rec.action_type} executed automatically.\n"
                            f"Target: {target_node}\n"
                            f"Attack: {prediction_label} (Severity: {severity})\n"
                            f"Confidence: {(top_rec.confidence_score or 0) * 100:.1f}%\n"
                            f"Status: COMPLETED at {datetime.utcnow().isoformat()}"
                        )

                        attack_log.status = "RESOLVED"
                        attack_log.resolved_at = datetime.utcnow()

                        if auto_incident:
                            auto_incident.status = "RESOLVED"
                            auto_incident.closed_at = datetime.utcnow()

                        # Update memory entry
                        memory_entry_update = (
                            db.query(models.AttackMemoryEntry)
                            .filter(
                                models.AttackMemoryEntry.attack_log_id
                                == attack_log_id
                            )
                            .first()
                        )
                        if memory_entry_update:
                            memory_entry_update.outcome = "RESOLVED"
                            memory_entry_update.success = True

                        db.commit()

                        # Broadcast auto-response event
                        await manager.broadcast(
                            {
                                "type": "auto_response",
                                "data": {
                                    "attack_log_id": attack_log_id,
                                    "attack_type": prediction_label,
                                    "severity": severity,
                                    "action_type": top_rec.action_type,
                                    "action_name": top_rec.title,
                                    "recovery_id": recovery.id,
                                    "status": "RESOLVED",
                                    "confidence": round(
                                        (top_rec.confidence_score or 0) * 100, 2
                                    ),
                                    "target_node": target_node,
                                    "timestamp": datetime.utcnow().isoformat(),
                                    "message": (
                                        f"Auto-response: {top_rec.action_type} executed "
                                        f"for {prediction_label} attack. "
                                        f"Target: {target_node}. Status: RESOLVED."
                                    ),
                                },
                            }
                        )

                        # Broadcast lifecycle updates
                        await manager.broadcast(
                            {
                                "type": "lifecycle_update",
                                "data": {
                                    "attack_log_id": attack_log_id,
                                    "status": "RESOLVED",
                                },
                            }
                        )

                        print(
                            f"[AUTO-RESPONSE] {top_rec.action_type} executed "
                            f"for AttackLog {attack_log_id} "
                            f"({prediction_label}/{severity})"
                        )

                except Exception as auto_error:

                    db.rollback()
                    print(
                        f"[AUTO-RESPONSE ERROR] "
                        f"AttackLog {attack_log_id}: {auto_error}"
                    )

        except Exception as error:

            print(
                "[REPLAY_SERVICE ERROR] "
                f"{error}"
            )

            if db is not None:

                try:
                    db.rollback()
                except Exception:
                    pass

            await asyncio.sleep(5)

        finally:

            if db is not None:
                db.close()


# =============================================================================
# LIFECYCLE MANAGER
# =============================================================================

async def lifecycle_manager_service():

    while True:

        await asyncio.sleep(5)

        try:

            db = SessionLocal()

            try:

                cutoff = (
                    datetime.utcnow()
                    - timedelta(
                        seconds=5
                    )
                )

                detected_logs = (
                    db.query(
                        models.AttackLog
                    )
                    .filter(
                        models.AttackLog.status
                        == "DETECTED",

                        models.AttackLog.created_at
                        <= cutoff,
                    )
                    .all()
                )

                for log in detected_logs:

                    log.status = "ANALYZING"

                    incident = (
                        db.query(
                            models.Incident
                        )
                        .filter(
                            models.Incident.attack_id
                            == log.id
                        )
                        .first()
                    )

                    if incident:
                        incident.status = (
                            "ANALYZING"
                        )

                    await manager.broadcast(
                        {
                            "type":
                                "lifecycle_update",

                            "data": {

                                "attack_log_id":
                                    log.id,

                                "status":
                                    "ANALYZING",
                            },
                        }
                    )

                if detected_logs:
                    db.commit()

            finally:

                db.close()

        except Exception as error:

            print(
                "[LIFECYCLE_MANAGER ERROR] "
                f"{error}"
            )


# =============================================================================
# LIVE METRICS
# =============================================================================

async def broadcast_metrics_loop():

    while True:

        await asyncio.sleep(2)

        try:

            db = SessionLocal()

            try:

                active_threats = (
                    db.query(
                        models.AttackLog
                    )
                    .filter(
                        models.AttackLog.attack_type
                        != "Normal",

                        ~models.AttackLog.status.in_(
                            ["RESOLVED"]
                        ),
                    )
                    .count()
                )

                today_start = (
                    datetime.utcnow()
                    .replace(
                        hour=0,
                        minute=0,
                        second=0,
                        microsecond=0,
                    )
                )

                resolved_today = (
                    db.query(
                        models.AttackLog
                    )
                    .filter(
                        models.AttackLog.attack_type
                        != "Normal",

                        models.AttackLog.status
                        == "RESOLVED",

                        models.AttackLog.resolved_at
                        >= today_start,
                    )
                    .count()
                )

                total_incidents = (
                    db.query(
                        models.Incident
                    ).count()
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

                risk_score_value = (
                    latest_risk.score
                    if latest_risk
                    else 0.0
                )

                systems_protected = (
                    db.query(
                        models.HospitalAsset
                    )
                    .filter(
                        models.HospitalAsset.status
                        == "ONLINE"
                    )
                    .count()
                )

                critical_alerts = (
                    db.query(
                        models.Alert
                    )
                    .filter(
                        models.Alert.severity
                        == "CRITICAL",

                        models.Alert.is_acknowledged
                        == False,
                    )
                    .count()
                )

                resolved_incidents = (
                    db.query(
                        models.Incident
                    )
                    .filter(
                        models.Incident.status
                        == "RESOLVED",

                        models.Incident.closed_at.isnot(
                            None
                        ),
                    )
                    .order_by(
                        models.Incident.closed_at.desc()
                    )
                    .limit(100)
                    .all()
                )

                if resolved_incidents:

                    avg_response = (
                        sum(
                            (
                                incident.closed_at
                                - incident.opened_at
                            ).total_seconds()

                            for incident
                            in resolved_incidents
                        )
                        / len(
                            resolved_incidents
                        )
                    )

                    avg_response_string = (
                        f"{avg_response:.1f}s"
                    )

                else:

                    avg_response_string = (
                        "0.0s"
                    )

                await manager.broadcast(
                    {
                        "type": "metrics",

                        "data": {

                            "active_threats":
                                active_threats,

                            "resolved_today":
                                resolved_today,

                            "total_incidents":
                                total_incidents,

                            "systems_protected":
                                systems_protected,

                            "critical_alerts":
                                critical_alerts,

                            "avg_response_time":
                                avg_response_string,

                            "risk_score":
                                risk_score_value,
                        },
                    }
                )

            finally:

                db.close()

        except Exception as error:

            print(
                "[METRICS_SERVICE ERROR] "
                f"{error}"
            )


# =============================================================================
# STARTUP
# =============================================================================

def seed_initial_data():
    db = SessionLocal()
    try:
        from auth import hash_password

        # ── Admin ─────────────────────────────────────────────────────────────
        admin_user = db.query(models.User).filter(models.User.email == settings.ADMIN_EMAIL).first()
        if not admin_user:
            admin_user = models.User(
                full_name=settings.ADMIN_NAME,
                email=settings.ADMIN_EMAIL,
                hashed_password=hash_password(settings.ADMIN_PASSWORD),
                role="admin",
                clearance_level=settings.ADMIN_CLEARANCE,
            )
            db.add(admin_user)
            db.commit()
            print(f"[ICDS-H] Admin seeded: {settings.ADMIN_EMAIL}")

        # ── Analyst (SOC Lead) ────────────────────────────────────────────────
        analyst_user = db.query(models.User).filter(models.User.email == settings.ANALYST_EMAIL).first()
        if not analyst_user:
            analyst_user = models.User(
                full_name=settings.ANALYST_NAME,
                email=settings.ANALYST_EMAIL,
                hashed_password=hash_password(settings.ANALYST_PASSWORD),
                role="analyst",
                clearance_level=settings.ANALYST_CLEARANCE,
            )
            db.add(analyst_user)
            db.commit()
            print(f"[ICDS-H] Analyst seeded: {settings.ANALYST_EMAIL}")

        # ── Clinical (MedDirector) ────────────────────────────────────────────
        clinical_user = db.query(models.User).filter(models.User.email == settings.CLINICAL_EMAIL).first()
        if not clinical_user:
            clinical_user = models.User(
                full_name=settings.CLINICAL_NAME,
                email=settings.CLINICAL_EMAIL,
                hashed_password=hash_password(settings.CLINICAL_PASSWORD),
                role="clinical",
                clearance_level=settings.CLINICAL_CLEARANCE,
            )
            db.add(clinical_user)
            db.commit()
            print(f"[ICDS-H] Clinical seeded: {settings.CLINICAL_EMAIL}")

        # ── Hospital Assets ───────────────────────────────────────────────────
        if db.query(models.HospitalAsset).count() == 0:
            sample_assets = [
                models.HospitalAsset(asset_name="Oncology Database EMR", asset_type="EMR Server", ip_address="10.0.0.20", criticality="CRITICAL", status="ONLINE"),
                models.HospitalAsset(asset_name="Radiology PACS Server", asset_type="Imaging System", ip_address="10.0.0.21", criticality="HIGH", status="ONLINE"),
                models.HospitalAsset(asset_name="Lab Pathology Cluster", asset_type="Laboratory Server", ip_address="10.0.0.22", criticality="HIGH", status="ONLINE"),
                models.HospitalAsset(asset_name="ICU Vital Monitor Node-04", asset_type="ICU Vital Monitoring", ip_address="10.0.0.23", criticality="CRITICAL", status="ONLINE"),
                models.HospitalAsset(asset_name="Hospital Public Web App", asset_type="Web Application", ip_address="10.0.0.5", criticality="MEDIUM", status="ONLINE"),
                models.HospitalAsset(asset_name="Active Directory Auth", asset_type="Authentication Service", ip_address="10.0.0.1", criticality="CRITICAL", status="ONLINE"),
            ]
            db.add_all(sample_assets)
            db.commit()
            print("[ICDS-H] Initial hospital assets seeded.")
    except Exception as e:
        print(f"[ICDS-H] Seeding notice: {e}")
        db.rollback()
    finally:
        db.close()


# =============================================================================
# LIVE PACKET CAPTURE SERVICE
# =============================================================================

async def live_capture_service():
    """Process live captured network packets through the full pipeline."""

    from cml.packet_capture import capture_engine, SCAPY_AVAILABLE

    if not SCAPY_AVAILABLE:
        print(
            "[LIVE_CAPTURE] Scapy not available. "
            "Live capture service will not start."
        )
        return

    # Configure and start capture
    capture_engine.interface = settings.CAPTURE_INTERFACE
    capture_engine.bpf_filter = settings.CAPTURE_BPF_FILTER
    capture_engine.batch_size = settings.CAPTURE_BATCH_SIZE

    started = await capture_engine.start()
    if not started:
        print("[LIVE_CAPTURE] Failed to start capture engine.")
        return

    from cml.dataset_engine import engine as dataset_engine

    await asyncio.sleep(5)  # Wait for capture to accumulate packets

    while True:
        try:
            await asyncio.sleep(REPLAY_INTERVAL_SECONDS)

            events = await capture_engine.get_events()

            if not events:
                continue

            for raw_event in events:
                db = None
                try:
                    db = SessionLocal()

                    raw_features = raw_event["raw_features"]

                    # Run through TON_IoT MLP (network traffic model)
                    try:
                        mlp_result = dataset_engine.predict_ton_iot(raw_features)
                    except Exception:
                        mlp_result = {
                            "prediction_label": "Normal",
                            "confidence": 50.0,
                            "risk_score": 10.0,
                            "severity": "LOW",
                            "model_version": "MLP_v5_LIVE",
                        }

                    prediction_label = mlp_result.get("prediction_label", "Normal")
                    confidence = float(mlp_result.get("confidence", 50.0))
                    risk_score = float(mlp_result.get("risk_score", 10.0))
                    severity = mlp_result.get("severity", "LOW")
                    model_version = mlp_result.get("model_version", "MLP_v5_LIVE")

                    # Anomaly detection
                    anomaly_result = anomaly_detector.detect_anomaly(
                        raw_features=raw_features,
                        dataset_source="TON_IoT",
                    )

                    is_attack = prediction_label != "Normal"

                    # Override if anomaly detected on normal traffic
                    if not is_attack and anomaly_result["is_anomaly"]:
                        prediction_label = "Anomaly (Zero-Day)"
                        severity = "HIGH"
                        is_attack = True

                    # Create attack log
                    dst_port = raw_features.get("dst_port")
                    try:
                        port_value = int(float(dst_port)) if dst_port is not None else None
                    except Exception:
                        port_value = None

                    attack_log = models.AttackLog(
                        attack_type=prediction_label,
                        source_ip=str(raw_features.get("src_ip", "LIVE")),
                        dest_ip=str(raw_features.get("dst_ip", "LIVE")),
                        protocol=str(raw_features.get("proto", "N/A")),
                        port=port_value,
                        severity=severity,
                        status="DETECTED",
                        suspicious_score=confidence,
                        raw_features=raw_features,
                        description=f"Live captured: {prediction_label} from {raw_features.get('src_ip', 'LIVE')}",
                        dataset_source="LIVE_CAPTURE",
                    )
                    db.add(attack_log)
                    db.flush()

                    # Anomaly record
                    anomaly_record = models.AnomalyDetection(
                        attack_log_id=attack_log.id,
                        anomaly_score=anomaly_result["anomaly_score"],
                        is_anomaly=anomaly_result["is_anomaly"],
                        detector_type=anomaly_result["detector_type"],
                        dataset_source="LIVE_CAPTURE",
                    )
                    db.add(anomaly_record)

                    # Risk score
                    risk_record = models.RiskScore(
                        attack_log_id=attack_log.id,
                        score=risk_score,
                        confidence=confidence,
                        model_version=model_version,
                        prediction_label=prediction_label,
                        node_id="LIVE_CAPTURE",
                        status="CRITICAL" if risk_score > 70 else "WARNING" if risk_score > 40 else "STABLE",
                    )
                    db.add(risk_record)

                    if is_attack and severity in ("MEDIUM", "HIGH", "CRITICAL"):
                        alert = models.Alert(
                            alert_type=prediction_label.upper().replace(" ", "_"),
                            title=f"{prediction_label} Detected [LIVE]",
                            message=f"Live capture: {prediction_label} | Confidence: {confidence:.1f}%",
                            severity=severity,
                            attack_log_id=attack_log.id,
                        )
                        db.add(alert)

                    db.commit()

                    # Broadcast
                    await manager.broadcast({
                        "type": "threat",
                        "data": {
                            "attack_log_id": attack_log.id,
                            "attack_type": prediction_label,
                            "severity": severity,
                            "confidence": round(confidence, 2),
                            "risk_score": round(risk_score, 1),
                            "dataset": "LIVE_CAPTURE",
                            "timestamp": datetime.utcnow().isoformat(),
                            "raw_features": raw_features,
                            "stage": "LIVE_DETECTED",
                            "anomaly_detection": anomaly_result,
                            "mlp_prediction": {
                                "label": prediction_label,
                                "confidence": round(confidence, 2),
                                "risk_score": round(risk_score, 1),
                                "model_version": model_version,
                                "dataset": "LIVE_CAPTURE",
                            },
                        },
                    })

                    if anomaly_result["is_anomaly"]:
                        await manager.broadcast({
                            "type": "anomaly_detection",
                            "data": {
                                "attack_log_id": attack_log.id,
                                "anomaly_score": anomaly_result["anomaly_score"],
                                "is_anomaly": True,
                                "detector_type": anomaly_result["detector_type"],
                                "dataset": "LIVE_CAPTURE",
                                "attack_type": prediction_label,
                                "severity": severity,
                            },
                        })

                except Exception as live_error:
                    print(f"[LIVE_CAPTURE ERROR] {live_error}")
                    if db:
                        try:
                            db.rollback()
                        except Exception:
                            pass
                finally:
                    if db:
                        db.close()

        except Exception as error:
            print(f"[LIVE_CAPTURE SERVICE ERROR] {error}")
            await asyncio.sleep(5)


@app.on_event("startup")
async def startup():
    # Capture the running event loop so synchronous endpoints (Attack Simulator)
    # can push events into the live WebSocket feed via broadcast_threadsafe().
    set_main_loop(asyncio.get_running_loop())

    seed_initial_data()

    # Train anomaly detector on existing dataset
    dataset_csv = os.path.join(
        os.path.dirname(__file__),
        "dataset",
        "unified_dataset.csv",
    )
    if os.path.exists(dataset_csv):
        import threading
        train_thread = threading.Thread(
            target=anomaly_detector.train_from_csv,
            args=(dataset_csv,),
            daemon=True,
        )
        train_thread.start()
        print("[ICDS-H] Anomaly detector training started in background.")
    else:
        print("[ICDS-H] No unified_dataset.csv found. Anomaly detector not trained.")

    asyncio.create_task(
        broadcast_metrics_loop()
    )

    asyncio.create_task(
        lifecycle_manager_service()
    )

    if DATASET_REPLAY_MODE:

        print(
            "[ICDS-H] DATASET_REPLAY_MODE=True "
            "- Starting automatic "
            "MLP -> Anomaly -> SHAP -> QIGA -> Auto-Response pipeline..."
        )

        asyncio.create_task(
            dataset_replay_service()
        )

    else:

        print(
            "[ICDS-H] DATASET_REPLAY_MODE=False "
            "- Awaiting external events."
        )

    if LIVE_CAPTURE_ENABLED:

        print(
            "[ICDS-H] LIVE_CAPTURE_ENABLED=True "
            "- Starting live packet capture service..."
        )

        asyncio.create_task(
            live_capture_service()
        )

    else:

        print(
            "[ICDS-H] LIVE_CAPTURE_ENABLED=False "
            "- Live capture disabled. "
            "Set LIVE_CAPTURE_ENABLED=True in .env to enable."
        )


# =============================================================================
# WEBSOCKET
# =============================================================================

@app.websocket("/ws/live")
async def websocket_endpoint(
    websocket: WebSocket,
):

    await manager.connect(websocket)

    try:

        while True:
            await websocket.receive_text()

    except WebSocketDisconnect:

        manager.disconnect(websocket)


# =============================================================================
# BASIC ENDPOINTS
# =============================================================================

@app.get("/")
@app.get("/api/")
def root():

    return {
        "message":
            "ICDS-H API is running",

        "version":
            "3.0.0",

        "dataset_replay_mode":
            DATASET_REPLAY_MODE,

        "live_capture_enabled":
            LIVE_CAPTURE_ENABLED,

        "auto_response_enabled":
            AUTO_RESPONSE_ENABLED,

        "anomaly_detector_status":
            anomaly_detector.get_status(),

        "automatic_flow": [

            "Dataset Replay / Live Packet Capture",

            "Dataset-specific MLP Prediction",

            "Isolation Forest Anomaly Detection",

            "AttackLog + RiskScore + AnomalyScore",

            "Monitoring Detection",

            "SHAP Explanation",

            "QIGA Optimization",

            "Recommendation",

            "Auto-Response (HIGH/CRITICAL) or Manual Approval",

            "Response / Recovery",
        ],

        "docs":
            "/docs",
    }


@app.get("/health")
@app.get("/api/health")
def health():

    return {
        "status":
            "healthy",

        "timestamp":
            datetime.utcnow().isoformat(),
    }