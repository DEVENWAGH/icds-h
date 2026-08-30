import requests

print("--- LATEST LOGS ---")
res = requests.get("http://localhost:8000/api/logs/latest")
for log in res.json()[:10]:
    print(f"ID: {log['attack_log_id']}, Type: {log['attack_type']}, Dataset: {log.get('dataset', 'Unknown')}, Features: {str(log['raw_features'])[:100]}")

print("\n--- INCIDENTS ---")
res = requests.get("http://localhost:8000/api/incidents")
for inc in res.json()[:5]:
    print(f"Incident ID: {inc['id']}, Attack ID: {inc['attack_id']}, Status: {inc['status']}")

print("\n--- RISK SCORES (Graph data) ---")
res = requests.get("http://localhost:8000/api/dashboard/risk-history")
for r in res.json()[:5]:
    print(f"Score: {r['risk']}, Time: {r['h']}")

print("\n--- DASHBOARD STATS ---")
res = requests.get("http://localhost:8000/api/monitoring/live")
print(res.json())
