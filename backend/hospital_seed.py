"""Create hospital departments, systems, assets, staff, and dummy patients."""

from sqlalchemy import inspect, text

import models
from auth import hash_password
from database import engine
from hospital_link import apply_asset_link

DEPARTMENTS = [
    ("CARD", "Cardiology", "Heart and vascular care"),
    ("ER", "Emergency", "Emergency department"),
    ("RAD", "Radiology", "Imaging services"),
    ("PATH", "Pathology", "Laboratory and pathology"),
    ("ICU", "ICU", "Intensive care"),
    ("ONC", "Oncology", "Cancer care"),
    ("FRONT", "Front Office", "Registration and reception"),
    ("ADMIN", "Administration", "Hospital administration"),
]

# ip, code, name, type, criticality, department code
ASSETS = [
    ("10.0.0.20", "A001", "EMR Server", "EMR Server", "CRITICAL", "ONC"),
    ("10.0.0.21", "A002", "PACS Server", "Imaging System", "HIGH", "RAD"),
    ("10.0.0.22", "A003", "LIS Server", "Laboratory Server", "HIGH", "PATH"),
    ("10.0.0.23", "A004", "ICU Monitor", "ICU Vital Monitoring", "CRITICAL", "ICU"),
    ("10.0.0.5", "A005", "Public Web App", "Web Application", "MEDIUM", "FRONT"),
    ("10.0.0.1", "A006", "AD Auth Server", "Authentication Service", "CRITICAL", "ADMIN"),
    ("10.0.0.30", "A007", "Registration Desk", "Registration Workstation", "MEDIUM", "FRONT"),
]

SYSTEMS = [
    ("EMR", "EMR System", "Electronic medical records", "A001", "ONC"),
    ("PACS", "PACS System", "Radiology imaging archive", "A002", "RAD"),
    ("LIS", "Laboratory System", "Lab orders and results", "A003", "PATH"),
    ("ICU-MON", "ICU Monitoring", "Bedside vital monitors", "A004", "ICU"),
    ("WEB", "Public Web", "Hospital public website", "A005", "FRONT"),
    ("AD", "Active Directory", "Staff authentication directory", "A006", "ADMIN"),
    ("REG", "Registration System", "Patient registration desk", "A007", "FRONT"),
]

STAFF = [
    ("Kavita Joshi", "hadmin@hospital.icds-h.com", "Hospital@1234", "hospital_admin", 4, "ADMIN"),
    ("Dr. Anil Rao", "doctor@hospital.icds-h.com", "Doctor@1234", "doctor", 3, "CARD"),
    ("Priya Deshmukh", "nurse@hospital.icds-h.com", "Nurse@1234", "nurse", 2, "CARD"),
    ("Imran Shaikh", "lab@hospital.icds-h.com", "LabTech@1234", "lab_technician", 2, "PATH"),
    ("Neha Kulkarni", "reception@hospital.icds-h.com", "Front@1234", "receptionist", 1, "FRONT"),
]

PATIENTS = [
    (
        "P-1001",
        "Aarav Shah",
        54,
        "CARD",
        "doctor@hospital.icds-h.com",
        "Vitals: BP 138/86, HR 88, Temp 37.1C\n"
        "Diagnosis: Unstable angina, admitted for monitoring\n"
        "Lab: Troponin I 0.08 ng/mL, CBC within range\n"
        "Notes: ECG shows ST depression. Cardiology consult completed.",
    ),
    (
        "P-1002",
        "Meera Iyer",
        67,
        "CARD",
        "doctor@hospital.icds-h.com",
        "Vitals: BP 150/92, HR 76, SpO2 96%\n"
        "Diagnosis: Congestive heart failure, NYHA II\n"
        "Lab: BNP 420 pg/mL, creatinine 1.2 mg/dL\n"
        "Notes: Daily weight stable. Continue diuretic.",
    ),
    (
        "P-1003",
        "Rohan Das",
        34,
        "ER",
        "doctor@hospital.icds-h.com",
        "Vitals: BP 118/74, HR 102, Temp 38.4C\n"
        "Diagnosis: Suspected appendicitis\n"
        "Lab: WBC 14.2, CRP elevated\n"
        "Notes: Surgical review requested from emergency.",
    ),
    (
        "P-1004",
        "Fatima Qureshi",
        29,
        "RAD",
        "doctor@hospital.icds-h.com",
        "Vitals: BP 110/70, HR 72, Temp 36.8C\n"
        "Diagnosis: Right ankle fracture follow-up\n"
        "Lab: No active lab orders\n"
        "Notes: PACS study XR-ANKLE-2041 available.",
    ),
    (
        "P-1005",
        "Joseph DSouza",
        72,
        "ICU",
        "doctor@hospital.icds-h.com",
        "Vitals: BP 96/60, HR 110, SpO2 91% on 4L\n"
        "Diagnosis: Sepsis secondary to pneumonia\n"
        "Lab: Lactate 3.1 mmol/L, blood culture pending\n"
        "Notes: ICU bed 4. Vasopressor started.",
    ),
    (
        "P-1006",
        "Ananya Krishnan",
        41,
        "ONC",
        "doctor@hospital.icds-h.com",
        "Vitals: BP 122/78, HR 80, Temp 36.9C\n"
        "Diagnosis: Breast carcinoma, cycle 3 chemotherapy\n"
        "Lab: ANC 1.4, platelets 160\n"
        "Notes: Cleared for today's infusion.",
    ),
    (
        "P-1007",
        "Vikram Singh",
        58,
        "PATH",
        "doctor@hospital.icds-h.com",
        "Vitals: BP 130/84, HR 70, Temp 36.7C\n"
        "Diagnosis: Anemia workup\n"
        "Lab: Hb 9.1 g/dL, ferritin low, B12 pending\n"
        "Notes: Pathology review of peripheral smear.",
    ),
    (
        "P-1008",
        "Priya Nambiar",
        23,
        "ER",
        "doctor@hospital.icds-h.com",
        "Vitals: BP 108/68, HR 88, Temp 37.0C\n"
        "Diagnosis: Closed wrist sprain\n"
        "Lab: None ordered\n"
        "Notes: Discharged from emergency with splint.",
    ),
]


def _column_names(conn, table, dialect):
    if dialect == "sqlite":
        rows = conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
        return {row[1] for row in rows}
    return {col["name"] for col in inspect(conn).get_columns(table)}


def _add_column(conn, table, name, ddl, dialect):
    if name in _column_names(conn, table, dialect):
        return
    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))


def migrate_hospital_schema():
    """Add hospital columns to tables that already exist."""
    dialect = engine.dialect.name
    tables = set(inspect(engine).get_table_names())
    with engine.begin() as conn:
        if "users" in tables:
            _add_column(conn, "users", "department_id", "INTEGER", dialect)
            _add_column(conn, "users", "updated_at", "DATETIME", dialect)
            if dialect != "sqlite":
                conn.execute(text("ALTER TABLE users MODIFY COLUMN role VARCHAR(32)"))
        if "hospital_assets" in tables:
            _add_column(conn, "hospital_assets", "asset_code", "VARCHAR(20)", dialect)
            _add_column(conn, "hospital_assets", "department_id", "INTEGER", dialect)
            _add_column(conn, "hospital_assets", "updated_at", "DATETIME", dialect)
        if "attack_logs" in tables:
            _add_column(conn, "attack_logs", "asset_id", "INTEGER", dialect)
            _add_column(conn, "attack_logs", "impact_line", "VARCHAR(255)", dialect)


def _dept_map(db):
    return {row.code: row for row in db.query(models.Department).all()}


def _asset_by_code(db):
    return {
        row.asset_code: row
        for row in db.query(models.HospitalAsset).all()
        if row.asset_code
    }


def seed_hospital(db):
    for code, name, description in DEPARTMENTS:
        row = db.query(models.Department).filter(models.Department.code == code).first()
        if not row:
            db.add(models.Department(code=code, name=name, description=description))
    db.flush()
    departments = _dept_map(db)

    for ip, code, name, asset_type, criticality, dept_code in ASSETS:
        row = (
            db.query(models.HospitalAsset)
            .filter(
                (models.HospitalAsset.ip_address == ip)
                | (models.HospitalAsset.asset_code == code)
            )
            .first()
        )
        department = departments.get(dept_code)
        if row:
            row.asset_code = code
            row.asset_name = name
            row.asset_type = asset_type
            row.criticality = criticality
            row.ip_address = ip
            if department:
                row.department_id = department.id
        else:
            db.add(
                models.HospitalAsset(
                    asset_code=code,
                    asset_name=name,
                    asset_type=asset_type,
                    ip_address=ip,
                    criticality=criticality,
                    status="ONLINE",
                    department_id=department.id if department else None,
                )
            )
    db.flush()
    assets = _asset_by_code(db)

    for code, name, description, asset_code, dept_code in SYSTEMS:
        row = db.query(models.HospitalSystem).filter(models.HospitalSystem.code == code).first()
        asset = assets.get(asset_code)
        department = departments.get(dept_code)
        if row:
            row.name = name
            row.description = description
            row.asset_id = asset.id if asset else None
            row.department_id = department.id if department else None
        else:
            db.add(
                models.HospitalSystem(
                    code=code,
                    name=name,
                    description=description,
                    asset_id=asset.id if asset else None,
                    department_id=department.id if department else None,
                )
            )
    db.flush()

    for full_name, email, password, role, clearance, dept_code in STAFF:
        row = db.query(models.User).filter(models.User.email == email).first()
        department = departments.get(dept_code)
        if row:
            continue
        db.add(
            models.User(
                full_name=full_name,
                email=email,
                hashed_password=hash_password(password),
                role=role,
                clearance_level=clearance,
                is_active=True,
                department_id=department.id if department else None,
            )
        )
    db.flush()

    doctor = db.query(models.User).filter(models.User.email == "doctor@hospital.icds-h.com").first()
    for code, name, age, dept_code, _doctor_email, record in PATIENTS:
        row = db.query(models.Patient).filter(models.Patient.patient_code == code).first()
        if row:
            continue
        department = departments.get(dept_code)
        db.add(
            models.Patient(
                patient_code=code,
                full_name=name,
                age=age,
                department_id=department.id if department else None,
                doctor_id=doctor.id if doctor else None,
                medical_record=record,
            )
        )
    db.flush()
    backfill_attack_assets(db)


def backfill_attack_assets(db):
    rows = (
        db.query(models.AttackLog)
        .filter(
            models.AttackLog.attack_type != "Normal",
            models.AttackLog.impact_line.is_(None),
        )
        .all()
    )
    for row in rows:
        apply_asset_link(db, row)
