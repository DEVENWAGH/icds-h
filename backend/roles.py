"""Role catalog for ICDS-H operators and hospital staff."""

SOC_ROLES = {"admin", "analyst", "clinical"}
HOSPITAL_ROLES = {
    "hospital_admin",
    "doctor",
    "nurse",
    "lab_technician",
    "receptionist",
}
ALL_ROLES = SOC_ROLES | HOSPITAL_ROLES

CLEARANCE = {
    "admin": 5,
    "hospital_admin": 4,
    "clinical": 4,
    "analyst": 3,
    "doctor": 3,
    "nurse": 2,
    "lab_technician": 2,
    "receptionist": 1,
}

# Clinical systems each role may open.
ROLE_SYSTEMS = {
    "admin": {"EMR", "PACS", "LIS", "ICU-MON", "REG", "AD", "WEB"},
    "hospital_admin": {"EMR", "PACS", "LIS", "ICU-MON", "REG", "AD", "WEB"},
    "clinical": {"EMR", "PACS", "LIS", "ICU-MON", "REG"},
    "analyst": set(),
    "doctor": {"EMR", "PACS", "LIS", "ICU-MON"},
    "nurse": {"EMR", "ICU-MON"},
    "lab_technician": {"LIS"},
    "receptionist": {"REG"},
}

ROLE_PERMISSIONS = {
    "admin": [
        "Full ICDS-H cybersecurity console",
        "Create hospital staff and assign any role",
        "Read every patient record and access log",
    ],
    "analyst": [
        "Full ICDS-H detection, response, and recovery console",
        "Monitor hospital access logs for suspicious behavior",
        "No clinical chart access",
    ],
    "clinical": [
        "Read hospital systems, patients, and access logs",
        "Review cybersecurity dashboard and alerts",
        "Cannot create staff accounts",
    ],
    "hospital_admin": [
        "Create doctors, nurses, lab technicians, and receptionists",
        "Assign each person a role and department",
        "Read patients, assets, and every access log",
    ],
    "doctor": [
        "Personal login",
        "Open EMR, PACS, LIS, and ICU monitoring",
        "Read and update medical records",
        "Opening a record outside the assigned department is logged and reviewed by ICDS-H",
    ],
    "nurse": [
        "Personal login",
        "Open EMR and ICU monitoring",
        "Read vital signs only",
        "Cannot update the medical record",
    ],
    "lab_technician": [
        "Personal login",
        "Open the laboratory system",
        "Read the lab section of a patient record",
    ],
    "receptionist": [
        "Personal login",
        "Open registration",
        "See patient id, name, age, department, and doctor",
        "Cannot open medical records",
    ],
}


def can_assign(actor_role, target_role):
    if target_role not in ALL_ROLES:
        return False
    if actor_role == "admin":
        return True
    if actor_role == "hospital_admin":
        return target_role in {"doctor", "nurse", "lab_technician", "receptionist"}
    return False
