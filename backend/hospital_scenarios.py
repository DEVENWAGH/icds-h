"""Showcase scenarios for hospital access monitoring.

Each story uses the same access-log path as a real staff login:
who signed in, which system they opened, and whether ICDS-H raised an alert
on the hospital asset.
"""

from sqlalchemy.orm import joinedload

import models
from hospital_audit import note_failed_login, record_event


class _Client:
    def __init__(self, host):
        self.host = host


class _Request:
    def __init__(self, ip, device):
        self.client = _Client(ip)
        self.headers = {"user-agent": device}


def _user(db, email):
    return db.query(models.User).filter(models.User.email == email).first()


def _patient(db, code):
    return (
        db.query(models.Patient)
        .options(joinedload(models.Patient.department))
        .filter(models.Patient.patient_code == code)
        .first()
    )


def _system(db, code):
    return (
        db.query(models.HospitalSystem)
        .options(joinedload(models.HospitalSystem.asset))
        .filter(models.HospitalSystem.code == code)
        .first()
    )


def _step(access, label, severity="HIGH"):
    attack = access.attack_log
    return {
        "attack_type": label,
        "severity": attack.severity if attack else severity,
        "attack_log_id": access.attack_log_id or access.id,
        "impact_line": attack.impact_line if attack else None,
        "success": access.success,
        "suspicious": access.suspicious,
    }


def run_clinical_chart_watch(db):
    """Doctor logs in, opens a Cardiology chart, then an ICU chart."""
    doctor = _user(db, "doctor@hospital.icds-h.com")
    own_patient = _patient(db, "P-1001")
    outside_patient = _patient(db, "P-1005")
    emr = _system(db, "EMR")
    if not all([doctor, own_patient, outside_patient, emr]):
        raise RuntimeError("Hospital staff and patients are not seeded")

    workstation = _Request("10.0.1.24", "Cardiology workstation")
    login = record_event(
        db,
        workstation,
        user=doctor,
        event_type="LOGIN",
        action="login",
        success=True,
        detail="Doctor signed in from the Cardiology ward",
    )
    clean = record_event(
        db,
        workstation,
        user=doctor,
        event_type="ACCESS",
        action="view_record",
        success=True,
        system=emr,
        asset=emr.asset,
        patient=own_patient,
        detail=f"Opened {own_patient.patient_code} in EMR",
    )
    flagged = record_event(
        db,
        workstation,
        user=doctor,
        event_type="ACCESS",
        action="view_record",
        success=True,
        system=emr,
        asset=emr.asset,
        patient=outside_patient,
        suspicious=True,
        suspicion_reason=(
            f"{doctor.full_name} opened {outside_patient.patient_code} "
            "outside their department via EMR System"
        ),
        attack_type="Insider Threat",
        severity="HIGH",
        detail=f"Cross-department chart open for {outside_patient.patient_code}",
    )
    return [
        _step(login, "Doctor login", "LOW"),
        _step(clean, "EMR chart in own department", "LOW"),
        _step(flagged, "Insider Threat"),
    ]


def run_blocked_record_open(db):
    """Receptionist tries to open a medical record and is denied."""
    receptionist = _user(db, "reception@hospital.icds-h.com")
    patient = _patient(db, "P-1001")
    emr = _system(db, "EMR")
    if not all([receptionist, patient, emr]):
        raise RuntimeError("Hospital staff and patients are not seeded")

    desk = _Request("10.0.1.30", "Front Office registration desk")
    denied = record_event(
        db,
        desk,
        user=receptionist,
        event_type="ACCESS",
        action="view_record",
        success=False,
        system=emr,
        asset=emr.asset,
        patient=patient,
        suspicious=True,
        suspicion_reason=f"{receptionist.role} is not allowed to open {emr.name}",
        attack_type="Insider Threat",
        severity="HIGH",
        detail="Receptionist attempted to open a medical record",
    )
    return [_step(denied, "Insider Threat")]


def run_staff_login_attack(db):
    """Three failed doctor logins become a password attack on the auth server."""
    email = "doctor@hospital.icds-h.com"
    doctor = _user(db, email)
    attacker = _Request("185.22.14.9", "Unknown browser")
    logs = []
    for _ in range(3):
        note_failed_login(db, attacker, email, doctor)
        logs.append(
            db.query(models.AccessLog)
            .filter(models.AccessLog.email == email, models.AccessLog.event_type == "LOGIN")
            .order_by(models.AccessLog.id.desc())
            .first()
        )
    return [_step(row, "Password Attack" if row.suspicious else "Failed staff login", "HIGH") for row in logs if row]
