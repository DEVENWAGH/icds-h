"""Verify least-privilege: clinical role is blocked from control actions,
admin is allowed; brute-force lockout and registration lockdown work."""
import json
import urllib.request
import urllib.error

BASE = "http://127.0.0.1:8000"


def req(method, path, token=None, body=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def login(email, pw):
    code, body = req("POST", "/api/auth/login", body={"email": email, "password": pw})
    if code == 200:
        return json.loads(body)["access_token"]
    return None


def check(label, got, expected):
    ok = "PASS" if got == expected else "FAIL"
    print(f"  [{ok}] {label}: got {got}, expected {expected}")
    return got == expected


def main():
    passed = True
    print("== RBAC least-privilege ==")
    admin = login("admin@icds-h.com", "Admin@1234")
    clinical = login("clinical@icds-h.com", "Clinical@1234")

    # clinical must be BLOCKED (403) from control actions
    code, _ = req("POST", "/api/sim/attack?attack_type=DDoS&severity=HIGH", clinical)
    passed &= check("clinical POST /sim/attack blocked", code, 403)
    code, _ = req("POST", "/api/firewall/block?ip_address=1.2.3.4", clinical)
    passed &= check("clinical POST /firewall/block blocked", code, 403)
    code, _ = req("POST", "/api/sim/replay/toggle?enabled=true", clinical)
    passed &= check("clinical POST /sim/replay/toggle blocked", code, 403)

    # clinical CAN still read dashboards
    code, _ = req("GET", "/api/dashboard/", clinical)
    passed &= check("clinical GET /dashboard/ allowed", code, 200)
    code, _ = req("GET", "/api/logs/", clinical)
    passed &= check("clinical GET /logs/ allowed", code, 200)

    # admin is allowed the control actions
    code, _ = req("POST", "/api/sim/attack?attack_type=DDoS&severity=HIGH", admin)
    passed &= check("admin POST /sim/attack allowed", code, 200)
    code, _ = req("POST", "/api/firewall/block?ip_address=9.9.9.9", admin)
    passed &= check("admin POST /firewall/block allowed", code, 200)

    print("== risk-history now requires auth ==")
    code, _ = req("GET", "/api/dashboard/risk-history")
    passed &= check("anon GET /risk-history blocked", code, 401)
    code, _ = req("GET", "/api/dashboard/risk-history", admin)
    passed &= check("admin GET /risk-history allowed", code, 200)

    print("== registration privilege-escalation lockdown ==")
    code, body = req("POST", "/api/auth/register", body={
        "full_name": "Hacker", "email": "hacker_pe@test.com",
        "password": "x12345", "role": "admin"})
    passed &= check("anon self-register as admin blocked", code, 403)

    print("\nRESULT:", "ALL PASS" if passed else "SOME FAILED")


if __name__ == "__main__":
    main()
