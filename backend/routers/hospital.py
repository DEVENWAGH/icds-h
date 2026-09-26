from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session, joinedload

import models
import schemas
from auth import get_current_user, hash_password
from database import get_db
from hospital_audit import record_event
from roles import (
    ALL_ROLES,
    CLEARANCE,
    ROLE_PERMISSIONS,
    ROLE_SYSTEMS,
    can_assign,
)

router = APIRouter(prefix="/api/hospital", tags=["Hospital"])

PATIENT_ROLES = {
    "admin",
    "clinical",
    "hospital_admin",
    "doctor",
    "nurse",
    "lab_technician",
    "receptionist",
}
LOG_ROLES = PATIENT_ROLES | {"analyst"}
STAFF_ROLES = {"admin", "hospital_admin"}
RECORD_ACTIONS = {"view_record", "view_patient", "view_lab", "update_record", "check_in"}
CHART_ROLES = {"doctor", "nurse"}


def _section(record, header):
    if not record:
        return ""
    matched = [
        line
        for line in record.splitlines()
        if line.lower().startswith(header.lower())
    ]
    return "\n".join(matched)


def _patient_brief(patient):
    return {
        "id": patient.id,
        "patient_code": patient.patient_code,
        "full_name": patient.full_name,
        "age": patient.age,
        "department": patient.department.name if patient.department else None,
        "department_code": patient.department.code if patient.department else None,
        "doctor": patient.doctor.full_name if patient.doctor else None,
    }


def _visible_record(user, patient, action):
    payload = _patient_brief(patient)
    record = patient.medical_record or ""
    if user.role == "receptionist" or action == "check_in":
        return payload
    if user.role == "nurse":
        payload["medical_record"] = _section(record, "Vitals")
        return payload
    if user.role == "lab_technician" or action == "view_lab":
        payload["medical_record"] = _section(record, "Lab")
        return payload
    payload["medical_record"] = record
    return payload


def _user_payload(user):
    return {
        "id": user.id,
        "full_name": user.full_name,
        "email": user.email,
        "role": user.role,
        "is_active": user.is_active,
        "clearance_level": user.clearance_level,
        "department_code": user.department.code if user.department else None,
        "department": user.department.name if user.department else None,
        "permissions": ROLE_PERMISSIONS.get(user.role, []),
    }


def _load_patient(db, patient_id):
    return (
        db.query(models.Patient)
        .options(
            joinedload(models.Patient.department),
            joinedload(models.Patient.doctor),
        )
        .filter(models.Patient.id == patient_id)
        .first()
    )


@router.get("/overview")
def overview(db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    departments = db.query(models.Department).order_by(models.Department.name).all()
    systems = (
        db.query(models.HospitalSystem)
        .options(joinedload(models.HospitalSystem.asset), joinedload(models.HospitalSystem.department))
        .order_by(models.HospitalSystem.code)
        .all()
    )
    assets = (
        db.query(models.HospitalAsset)
        .options(joinedload(models.HospitalAsset.department))
        .order_by(models.HospitalAsset.asset_code)
        .all()
    )
    return {
        "permissions": ROLE_PERMISSIONS.get(current_user.role, []),
        "role": current_user.role,
        "counts": {
            "departments": len(departments),
            "systems": len(systems),
            "assets": len(assets),
            "patients": db.query(models.Patient).count(),
            "staff": db.query(models.User).filter(models.User.role.in_(list(ALL_ROLES))).count(),
        },
        "departments": [
            {
                "id": row.id,
                "code": row.code,
                "name": row.name,
                "description": row.description,
            }
            for row in departments
        ],
        "systems": [
            {
                "id": row.id,
                "code": row.code,
                "name": row.name,
                "description": row.description,
                "department": row.department.name if row.department else None,
                "asset_code": row.asset.asset_code if row.asset else None,
                "asset_name": row.asset.asset_name if row.asset else None,
                "asset_ip": row.asset.ip_address if row.asset else None,
            }
            for row in systems
        ],
        "assets": [
            {
                "id": row.id,
                "asset_code": row.asset_code,
                "asset_name": row.asset_name,
                "asset_type": row.asset_type,
                "ip_address": row.ip_address,
                "criticality": row.criticality,
                "status": row.status,
                "department": row.department.name if row.department else None,
            }
            for row in assets
        ],
    }


@router.get("/patients")
def list_patients(db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    if current_user.role not in PATIENT_ROLES:
        raise HTTPException(status_code=403, detail="Patient records are limited to clinical roles")
    rows = (
        db.query(models.Patient)
        .options(joinedload(models.Patient.department), joinedload(models.Patient.doctor))
        .order_by(models.Patient.patient_code)
        .all()
    )
    return [_patient_brief(row) for row in rows]


@router.post("/access")
def access_system(
    body: schemas.HospitalAccessIn,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    action = body.action.strip().lower()
    if action not in RECORD_ACTIONS:
        raise HTTPException(status_code=400, detail=f"Unknown action. Choose from: {sorted(RECORD_ACTIONS)}")

    system = (
        db.query(models.HospitalSystem)
        .options(joinedload(models.HospitalSystem.asset))
        .filter(models.HospitalSystem.code == body.system_code.strip().upper())
        .first()
    )
    if not system:
        raise HTTPException(status_code=404, detail="Hospital system not found")

    patient = None
    if body.patient_id is not None:
        patient = _load_patient(db, body.patient_id)
        if not patient:
            raise HTTPException(status_code=404, detail="Patient not found")
    elif action != "check_in":
        raise HTTPException(status_code=400, detail="patient_id is required for this action")

    allowed = system.code in ROLE_SYSTEMS.get(current_user.role, set())
    suspicious = False
    reason = None
    attack_type = None

    if not allowed:
        suspicious = True
        reason = f"{current_user.role} is not allowed to open {system.name}"
        attack_type = "Insider Threat"
    elif action == "update_record" and current_user.role not in {"doctor", "admin", "hospital_admin", "clinical"}:
        allowed = False
        suspicious = True
        reason = f"{current_user.role} cannot update a medical record"
        attack_type = "Insider Threat"
    elif (
        patient
        and current_user.role in CHART_ROLES
        and patient.department_id
        and current_user.department_id
        and patient.department_id != current_user.department_id
    ):
        suspicious = True
        reason = (
            f"{current_user.full_name} opened {patient.patient_code} "
            f"outside their department via {system.name}"
        )
        attack_type = "Insider Threat"
    elif action in {"view_record", "view_patient", "view_lab"} and patient:
        since = datetime.utcnow() - timedelta(minutes=2)
        recent = (
            db.query(models.AccessLog)
            .filter(
                models.AccessLog.user_id == current_user.id,
                models.AccessLog.success == True,
                models.AccessLog.action.in_(["view_record", "view_patient", "view_lab"]),
                models.AccessLog.created_at >= since,
            )
            .count()
        )
        if recent + 1 >= 5:
            suspicious = True
            reason = f"{current_user.full_name} opened {recent + 1} patient records in two minutes"
            attack_type = "Insider Threat"

    asset = system.asset
    record_event(
        db,
        request,
        user=current_user,
        event_type="ACCESS",
        action=action,
        success=allowed,
        system=system,
        asset=asset,
        patient=patient,
        detail=reason or f"{action} on {system.code}",
        suspicious=suspicious,
        suspicion_reason=reason,
        attack_type=attack_type,
        severity="HIGH",
    )
    db.commit()

    if not allowed:
        raise HTTPException(status_code=403, detail=reason)

    payload = {
        "success": True,
        "suspicious": suspicious,
        "message": reason or "Access granted and activity logged",
        "chain": [
            current_user.role,
            "Login",
            system.name,
            action,
            "Activity Logged",
        ],
        "system": {
            "code": system.code,
            "name": system.name,
            "asset_code": asset.asset_code if asset else None,
            "asset_name": asset.asset_name if asset else None,
        },
        "patient": _visible_record(current_user, patient, action) if patient else None,
    }
    return payload


@router.get("/access-logs")
def access_logs(
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    if current_user.role not in LOG_ROLES:
        raise HTTPException(status_code=403, detail="Access logs are restricted")
    query = (
        db.query(models.AccessLog)
        .options(
            joinedload(models.AccessLog.hospital_system),
            joinedload(models.AccessLog.asset),
            joinedload(models.AccessLog.patient),
            joinedload(models.AccessLog.attack_log),
        )
        .order_by(models.AccessLog.created_at.desc())
    )
    if current_user.role not in {"admin", "analyst", "clinical", "hospital_admin"}:
        query = query.filter(models.AccessLog.user_id == current_user.id)
    rows = query.limit(min(limit, 300)).all()
    return [
        {
            "id": row.id,
            "who": row.full_name or row.email or "Unknown",
            "email": row.email,
            "role": row.role,
            "event_type": row.event_type,
            "action": row.action,
            "system": row.hospital_system.name if row.hospital_system else None,
            "system_code": row.hospital_system.code if row.hospital_system else None,
            "asset_name": row.asset.asset_name if row.asset else None,
            "asset_code": row.asset.asset_code if row.asset else None,
            "patient_code": row.patient.patient_code if row.patient else None,
            "success": row.success,
            "ip_address": row.ip_address,
            "device": row.device,
            "detail": row.detail,
            "suspicious": row.suspicious,
            "suspicion_reason": row.suspicion_reason,
            "attack_log_id": row.attack_log_id,
            "impact_line": row.attack_log.impact_line if row.attack_log else None,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }
        for row in rows
    ]


@router.get("/users")
def list_users(db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    if current_user.role not in STAFF_ROLES:
        raise HTTPException(status_code=403, detail="Staff management requires a hospital or ICDS admin")
    rows = (
        db.query(models.User)
        .options(joinedload(models.User.department))
        .order_by(models.User.id)
        .all()
    )
    return [_user_payload(row) for row in rows]


@router.post("/users")
def create_user(
    body: schemas.HospitalUserCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    if current_user.role not in STAFF_ROLES:
        raise HTTPException(status_code=403, detail="Only an admin can create hospital users")
    role = body.role.strip().lower()
    if not can_assign(current_user.role, role):
        raise HTTPException(status_code=403, detail="You cannot assign that role")
    existing = db.query(models.User).filter(models.User.email == body.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    department = None
    if body.department_code:
        department = (
            db.query(models.Department)
            .filter(models.Department.code == body.department_code.strip().upper())
            .first()
        )
        if not department:
            raise HTTPException(status_code=400, detail="Unknown department")
    user = models.User(
        full_name=body.full_name.strip(),
        email=str(body.email).lower(),
        hashed_password=hash_password(body.password),
        role=role,
        clearance_level=CLEARANCE.get(role, 1),
        is_active=True,
        department_id=department.id if department else None,
    )
    db.add(user)
    db.flush()
    record_event(
        db,
        request,
        user=current_user,
        event_type="ADMIN",
        action="create_user",
        success=True,
        detail=f"Created {user.email} as {role}",
    )
    db.commit()
    db.refresh(user)
    return _user_payload(user)


@router.patch("/users/{user_id}")
def update_user(
    user_id: int,
    body: schemas.HospitalUserUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    if current_user.role not in STAFF_ROLES:
        raise HTTPException(status_code=403, detail="Only an admin can update hospital users")
    target = (
        db.query(models.User)
        .options(joinedload(models.User.department))
        .filter(models.User.id == user_id)
        .first()
    )
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if body.is_active is False and target.id == current_user.id:
        raise HTTPException(status_code=400, detail="You cannot deactivate your own account")
    if body.role is not None:
        role = body.role.strip().lower()
        if not can_assign(current_user.role, role):
            raise HTTPException(status_code=403, detail="You cannot assign that role")
        if target.id == current_user.id and role != current_user.role:
            raise HTTPException(status_code=400, detail="You cannot change your own role")
        target.role = role
        target.clearance_level = CLEARANCE.get(role, target.clearance_level)
    if body.is_active is not None:
        target.is_active = body.is_active
    if body.department_code is not None:
        department = (
            db.query(models.Department)
            .filter(models.Department.code == body.department_code.strip().upper())
            .first()
        )
        if not department:
            raise HTTPException(status_code=400, detail="Unknown department")
        target.department_id = department.id
    record_event(
        db,
        request,
        user=current_user,
        event_type="ADMIN",
        action="update_user",
        success=True,
        detail=f"Updated {target.email}",
    )
    db.commit()
    db.refresh(target)
    return _user_payload(target)
