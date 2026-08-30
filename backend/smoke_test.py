"""
ICDS-H API smoke test. Hits every endpoint and reports status.
Run with the backend already up on http://127.0.0.1:8000.
"""
import json
import sys
import urllib.request
import urllib.error

BASE = "http://127.0.0.1:8000"
ADMIN = {"email": "admin@icds-h.com", "password": "Admin@1234"}

results = []


def call(method, path, token=None, body=None, expect=(200,)):
    url = BASE + path
    data = None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            code = resp.status
            raw = resp.read().decode()
    except urllib.error.HTTPError as e:
        code = e.code
        raw = e.read().decode()
    except Exception as e:  # noqa
        results.append((method, path, "ERR", str(e)[:80]))
        return None
    ok = "OK" if code in expect else "FAIL"
    snippet = raw[:70].replace("\n", " ")
    results.append((method, path, f"{code} {ok}", snippet))
    try:
        return json.loads(raw)
    except Exception:  # noqa
        return None


def main():
    # public
    call("GET", "/health")
    call("GET", "/api/health")
    call("GET", "/api/")
    call("GET", "/api/dashboard/risk-history")

    login = call("POST", "/api/auth/login", body=ADMIN)
    if not login or "access_token" not in login:
        print("LOGIN FAILED - aborting")
        for r in results:
            print(r)
        sys.exit(1)
    tok = login["access_token"]

    call("GET", "/api/auth/me", tok)

    # fire an attack so we have a valid attack_log_id with full pipeline
    atk = call("POST", "/api/sim/attack?attack_type=Ransomware&severity=CRITICAL", tok)
    log_id = atk.get("attack_log_id") if atk else None

    call("POST", "/api/sim/anomaly?severity=HIGH", tok)
    call("GET", "/api/sim/types", tok)
    call("GET", "/api/sim/replay/status", tok)

    call("GET", "/api/logs/", tok)
    call("GET", "/api/logs/latest?limit=10", tok)
    call("GET", "/api/logs/stats", tok)

    call("GET", "/api/alerts/", tok)
    call("GET", "/api/alerts/unacknowledged/count", tok)

    call("GET", "/api/dashboard/", tok)

    call("GET", "/api/incidents/", tok)
    call("GET", "/api/assets/", tok)

    call("GET", "/api/monitoring/live", tok)
    call("GET", "/api/monitoring/history?limit=10", tok)

    for ds in ("TON_IoT", "PhiUSIIL", "CERT"):
        call("GET", f"/api/predict/metrics?dataset={ds}", tok)
        call("GET", f"/api/predict/model-info?dataset={ds}", tok)
    call("GET", "/api/predict/latest?limit=5", tok)

    call("GET", "/api/firewall/rules?active_only=true", tok)
    call("GET", "/api/firewall/stats", tok)

    call("GET", "/api/memory/stats", tok)
    call("GET", "/api/memory/history?limit=10", tok)

    call("GET", "/api/optimize/latest?limit=10", tok)

    call("GET", "/api/admin/users", tok)
    call("GET", "/api/admin/stats", tok)

    if log_id:
        call("GET", f"/api/xai/explain/{log_id}", tok)
        call("GET", f"/api/predict/{log_id}", tok)
        call("GET", f"/api/recommendations/?attack_log_id={log_id}&limit=10", tok)
        call("GET", f"/api/recovery/?attack_log_id={log_id}&limit=10", tok)
        call("GET", f"/api/memory/similar?attack_log_id={log_id}&k=5", tok)
        call("POST", f"/api/optimize/?attack_log_id={log_id}", tok)

    # scenario (all keys)
    for sc in ("hospital_breach", "apt_intrusion", "zero_day_outbreak", "memory_recall"):
        call("POST", f"/api/sim/scenario?scenario={sc}", tok)

    print(f"\n{'METHOD':7} {'PATH':52} {'STATUS':10} SNIPPET")
    print("-" * 110)
    fails = 0
    for m, p, s, snip in results:
        if "OK" not in s:
            fails += 1
        print(f"{m:7} {p:52} {s:10} {snip}")
    print("-" * 110)
    print(f"TOTAL: {len(results)}  FAILURES: {fails}")


if __name__ == "__main__":
    main()
