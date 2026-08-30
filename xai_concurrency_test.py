"""Fire many concurrent /xai/explain requests to verify the SHAP thread-safety fix."""
import concurrent.futures
import json
import urllib.request
import urllib.error

BASE = "http://127.0.0.1:8000"


def login():
    req = urllib.request.Request(
        BASE + "/api/auth/login",
        data=json.dumps({"email": "admin@icds-h.com", "password": "Admin@1234"}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())["access_token"]


def fire_attack(tok):
    req = urllib.request.Request(
        BASE + "/api/sim/attack?attack_type=DDoS&severity=HIGH",
        headers={"Authorization": f"Bearer {tok}"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())["attack_log_id"]


def explain(tok, log_id):
    req = urllib.request.Request(
        BASE + f"/api/xai/explain/{log_id}",
        headers={"Authorization": f"Bearer {tok}"}, method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return f"{e.code}:{e.read().decode()[:60]}"
    except Exception as e:  # noqa
        return f"ERR:{e}"


def main():
    tok = login()
    log_id = fire_attack(tok)
    print(f"Testing 20 concurrent /xai/explain for log #{log_id}")
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        futures = [ex.submit(explain, tok, log_id) for _ in range(20)]
        codes = [f.result() for f in concurrent.futures.as_completed(futures)]
    ok = sum(1 for c in codes if c == 200)
    print(f"200 OK: {ok}/20")
    bad = [c for c in codes if c != 200]
    if bad:
        print("FAILURES:")
        for b in bad:
            print("  ", b)
    else:
        print("ALL CONCURRENT REQUESTS SUCCEEDED - fix confirmed")


if __name__ == "__main__":
    main()
