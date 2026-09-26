"""End-to-end checks for hospital staff, patients, access logs, and asset-linked attacks."""
import json
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:8000"


def req(method, path, token=None, body=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read().decode()
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as error:
        raw = error.read().decode()
        try:
            payload = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            payload = raw
        return error.code, payload


def login(email, password):
    code, body = req("POST", "/api/auth/login", body={"email": email, "password": password})
    if code != 200:
        raise SystemExit(f"login failed for {email}: {code} {body}")
    return body["access_token"], body["user"]


def check(label, condition, detail=""):
    text = f"  [{'PASS' if condition else 'FAIL'}] {label} {detail}"
    print(text.encode("ascii", "replace").decode())
    return bool(condition)


def main():
    passed = True
    print("== hospital directory ==")
    admin_token, admin = login("admin@icds-h.com", "Admin@1234")
    passed &= check("admin role", admin["role"] == "admin")

    code, overview = req("GET", "/api/hospital/overview", admin_token)
    codes = {row["asset_code"] for row in overview["assets"]}
    passed &= check("overview 200", code == 200)
    passed &= check("EMR asset A001 present", "A001" in codes, str(sorted(codes)))
    passed &= check("eight departments", len(overview["departments"]) >= 8)
    passed &= check("EMR system linked", any(row["code"] == "EMR" and row["asset_code"] == "A001" for row in overview["systems"]))

    print("== doctor chart access ==")
    doctor_token, doctor = login("doctor@hospital.icds-h.com", "Doctor@1234")
    passed &= check("doctor role", doctor["role"] == "doctor")
    code, patients = req("GET", "/api/hospital/patients", doctor_token)
    passed &= check("doctor sees patients", code == 200 and len(patients) >= 8, f"count={len(patients) if isinstance(patients, list) else patients}")
    cardio = next(row for row in patients if row["patient_code"] == "P-1001")
    icu = next(row for row in patients if row["patient_code"] == "P-1005")

    code, opened = req("POST", "/api/hospital/access", doctor_token, {
        "system_code": "EMR",
        "action": "view_record",
        "patient_id": cardio["id"],
    })
    record = (opened or {}).get("patient", {}).get("medical_record", "")
    passed &= check("doctor opens own-department chart", code == 200 and "Diagnosis" in record)
    passed &= check("doctor chain logged", "Activity Logged" in ((opened or {}).get("chain") or []))
    passed &= check("same-department access is not suspicious", (opened or {}).get("suspicious") is False)

    code, outside = req("POST", "/api/hospital/access", doctor_token, {
        "system_code": "EMR",
        "action": "view_record",
        "patient_id": icu["id"],
    })
    passed &= check("cross-department open still returns the chart", code == 200)
    passed &= check("cross-department open is flagged", (outside or {}).get("suspicious") is True)

    print("== role permissions ==")
    nurse_token, _nurse = login("nurse@hospital.icds-h.com", "Nurse@1234")
    code, vitals = req("POST", "/api/hospital/access", nurse_token, {
        "system_code": "EMR",
        "action": "view_record",
        "patient_id": cardio["id"],
    })
    nurse_record = (vitals or {}).get("patient", {}).get("medical_record", "")
    passed &= check("nurse sees vitals", code == 200 and nurse_record.startswith("Vitals"))
    passed &= check("nurse does not see the diagnosis", "Diagnosis" not in nurse_record)

    lab_token, _lab = login("lab@hospital.icds-h.com", "LabTech@1234")
    code, lab = req("POST", "/api/hospital/access", lab_token, {
        "system_code": "LIS",
        "action": "view_lab",
        "patient_id": cardio["id"],
    })
    lab_record = (lab or {}).get("patient", {}).get("medical_record", "")
    passed &= check("lab tech sees lab section", code == 200 and lab_record.startswith("Lab"))

    desk_token, _desk = login("reception@hospital.icds-h.com", "Front@1234")
    code, denied = req("POST", "/api/hospital/access", desk_token, {
        "system_code": "EMR",
        "action": "view_record",
        "patient_id": cardio["id"],
    })
    passed &= check("receptionist blocked from EMR", code == 403, str(denied))

    analyst_token, _analyst = login("analyst@icds-h.com", "Analyst@1234")
    code, _blocked = req("GET", "/api/hospital/patients", analyst_token)
    passed &= check("analyst cannot read charts", code == 403)
    code, logs = req("GET", "/api/hospital/access-logs?limit=50", analyst_token)
    suspicious = [row for row in logs if row.get("suspicious")]
    passed &= check("analyst can read access logs", code == 200 and len(logs) >= 4)
    passed &= check(
        "suspicious access linked to EMR asset",
        any(row.get("impact_line") and "EMR Server (A001)" in row["impact_line"] for row in suspicious),
        str([row.get("impact_line") for row in suspicious]),
    )

    print("== staff provisioning ==")
    hadmin_token, hadmin = login("hadmin@hospital.icds-h.com", "Hospital@1234")
    passed &= check("hospital admin role", hadmin["role"] == "hospital_admin")
    code, created = req("POST", "/api/hospital/users", hadmin_token, {
        "full_name": "Test Nurse Two",
        "email": "nurse2@hospital.icds-h.com",
        "password": "Nurse@1234",
        "role": "nurse",
        "department_code": "ER",
    })
    passed &= check("hospital admin creates a nurse", code == 200 and created["role"] == "nurse", str(created if code != 200 else created["email"]))
    code, blocked_admin = req("POST", "/api/hospital/users", hadmin_token, {
        "full_name": "Should Fail",
        "email": "notadmin@hospital.icds-h.com",
        "password": "Admin@1234",
        "role": "admin",
        "department_code": "ADMIN",
    })
    passed &= check("hospital admin cannot create an ICDS admin", code == 403, str(blocked_admin))

    print("== attacks name the hospital asset ==")
    code, latest = req("GET", "/api/logs/latest?limit=30", admin_token)
    linked = [row for row in latest if row.get("impact_line")]
    passed &= check("attack feed includes asset impact lines", code == 200 and len(linked) > 0)
    passed &= check(
        "impact line uses asset code and risk",
        any("→" in (row.get("impact_line") or "") and "Risk" in (row.get("impact_line") or "") for row in linked),
        (linked[0].get("impact_line") if linked else "none"),
    )

    print("== failed logins ==")
    for _ in range(3):
        req("POST", "/api/auth/login", body={"email": "doctor@hospital.icds-h.com", "password": "wrong-pass"})
    code, logs = req("GET", "/api/hospital/access-logs?limit=20", admin_token)
    failed = [row for row in logs if row.get("action") == "login" and row.get("success") is False]
    passed &= check("failed logins are recorded", len(failed) >= 3)
    passed &= check(
        "repeated failures become a password-attack alert",
        any(row.get("impact_line") and "AD Auth Server (A006)" in row["impact_line"] for row in failed),
        str([row.get("impact_line") for row in failed[:4]]),
    )

    print("\nRESULT:", "ALL PASS" if passed else "SOME FAILED")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
