"""Write hospital access logs and raise ICDS-H alerts for suspicious activity."""

from datetime import datetime, timedelta

from fastapi import Request

import models
from hospital_link import apply_asset_link, format_impact

SUSPICIOUS_WINDOW_MINUTES = 10
BULK_WINDOW_MINUTES = 2
BULK_RECORD_THRESHOLD = 5
FAILED_LOGIN_THRESHOLD = 3


def client_ip(request: Request) -> str:
    if request is None:
        return "unknown"
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()[:45]
    if request.client and request.client.host:
        return request.client.host[:45]
    return "unknown"


def client_device(request: Request) -> str:
    if request is None:
        return "unknown"
    return (request.headers.get("user-agent") or "unknown")[:255]


def _recent_hospital_attack(db, attack_type, email):
    since = datetime.utcnow() - timedelta(minutes=SUSPICIOUS_WINDOW_MINUTES)
    rows = (
        db.query(models.AttackLog)
        .filter(
            models.AttackLog.dataset_source == "HOSPITAL_ACCESS",
            models.AttackLog.attack_type == attack_type,
            models.AttackLog.detected_at >= since,
        )
        .all()
    )
    for row in rows:
        raw = row.raw_features or {}
        if raw.get("email") == email:
            return row
    return None


def raise_hospital_alert(db, *, user, email, attack_type, severity, asset, reason, detail):
    """Create an AttackLog, alert, and risk score so the existing SOC modules can see it."""
    existing = _recent_hospital_attack(db, attack_type, email)
    if existing:
        return existing

    score = {"CRITICAL": 92.0, "HIGH": 78.0, "MEDIUM": 55.0, "LOW": 25.0}.get(severity, 78.0)
    attack = models.AttackLog(
        attack_type=attack_type,
        source_ip=detail.get("ip_address"),
        dest_ip=asset.ip_address if asset else None,
        protocol="HOSPITAL",
        severity=severity,
        status="DETECTED",
        suspicious_score=score,
        description=reason,
        dataset_source="HOSPITAL_ACCESS",
        asset_id=asset.id if asset else None,
        raw_features={
            "email": email,
            "user_id": user.id if user else None,
            "role": user.role if user else None,
            "reason": reason,
            **detail,
        },
        failed_login_count=detail.get("failed_login_count"),
        user_behavior_score=score,
    )
    if asset and not attack.impact_line:
        attack.impact_line = format_impact(attack_type, asset, severity)
    db.add(attack)
    db.flush()
    apply_asset_link(db, attack)

    db.add(
        models.Alert(
            alert_type=attack_type.upper().replace(" ", "_"),
            title=attack.impact_line or attack_type,
            message=reason,
            severity=severity,
            attack_log_id=attack.id,
        )
    )
    db.add(
        models.RiskScore(
            attack_log_id=attack.id,
            score=score,
            confidence=score,
            risk_band=severity,
            model_version="HOSPITAL_ACCESS_v1",
            prediction_label=attack_type,
            node_id=asset.asset_code if asset else "HOSPITAL",
            status="CRITICAL" if score > 70 else "WARNING",
        )
    )
    return attack


def record_event(
    db,
    request,
    *,
    user=None,
    email=None,
    event_type,
    action,
    success,
    system=None,
    asset=None,
    patient=None,
    detail=None,
    suspicious=False,
    suspicion_reason=None,
    attack_type=None,
    severity="HIGH",
):
    resolved_email = email or (user.email if user else None)
    access = models.AccessLog(
        user_id=user.id if user else None,
        email=resolved_email,
        full_name=user.full_name if user else None,
        role=user.role if user else None,
        event_type=event_type,
        action=action,
        hospital_system_id=system.id if system else None,
        asset_id=asset.id if asset else (system.asset_id if system else None),
        patient_id=patient.id if patient else None,
        success=success,
        ip_address=client_ip(request),
        device=client_device(request),
        detail=detail,
        suspicious=suspicious,
        suspicion_reason=suspicion_reason,
    )
    db.add(access)
    db.flush()

    if suspicious and attack_type:
        linked_asset = asset
        if linked_asset is None and system is not None and system.asset_id:
            linked_asset = db.get(models.HospitalAsset, system.asset_id)
        attack = raise_hospital_alert(
            db,
            user=user,
            email=resolved_email,
            attack_type=attack_type,
            severity=severity,
            asset=linked_asset,
            reason=suspicion_reason or detail or attack_type,
            detail={
                "ip_address": access.ip_address,
                "device": access.device,
                "action": action,
                "patient_code": patient.patient_code if patient else None,
                "system_code": system.code if system else None,
            },
        )
        if attack is not None:
            access.attack_log_id = attack.id
    return access


def note_failed_login(db, request, email, user=None):
    since = datetime.utcnow() - timedelta(minutes=SUSPICIOUS_WINDOW_MINUTES)
    failures = (
        db.query(models.AccessLog)
        .filter(
            models.AccessLog.email == email,
            models.AccessLog.event_type == "LOGIN",
            models.AccessLog.success == False,
            models.AccessLog.created_at >= since,
        )
        .count()
    )
    # This attempt is about to be recorded, so include it.
    failures += 1
    suspicious = failures >= FAILED_LOGIN_THRESHOLD
    asset = (
        db.query(models.HospitalAsset)
        .filter(models.HospitalAsset.asset_code == "A006")
        .first()
    )
    record_event(
        db,
        request,
        user=user,
        email=email,
        event_type="LOGIN",
        action="login",
        success=False,
        asset=asset,
        detail="Invalid credentials",
        suspicious=suspicious,
        suspicion_reason=(
            f"{failures} failed logins for {email}" if suspicious else None
        ),
        attack_type="Password Attack" if suspicious else None,
        severity="HIGH",
    )
    db.commit()


def note_successful_login(db, request, user):
    record_event(
        db,
        request,
        user=user,
        event_type="LOGIN",
        action="login",
        success=True,
        detail="Login succeeded",
    )
    db.commit()
