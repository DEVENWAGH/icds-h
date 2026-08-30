"""
ICDS-H maintenance: clear old logs / attack history.

Deletes all transactional records (attack logs, alerts, incidents, risk scores,
recommendations, recovery actions, QIGA results, anomaly detections, firewall
rules, attack memory, monitoring history) while KEEPING:
    - User accounts (users)
    - Hospital assets (hospital_assets)

Usage (from the backend/ folder):
    python clear_logs.py

The backend can stay running; this only deletes rows, it does not touch the
SQLite file. Refresh the browser afterwards to clear the on-screen live feed.
"""

from database import SessionLocal
import models

# Order matters: delete child tables (which hold foreign keys) before parents.
DELETE_ORDER = [
    models.RecoveryAction,      # -> recommendations
    models.Recommendation,      # -> attack_logs
    models.Alert,               # -> attack_logs
    models.RiskScore,           # -> attack_logs
    models.Incident,            # -> attack_logs
    models.QIGAResult,          # -> attack_logs
    models.AttackMemoryEntry,   # -> attack_logs
    models.FirewallRule,        # -> attack_logs
    models.AnomalyDetection,    # -> attack_logs
    models.MonitoringHistory,   # no FK
    models.AttackLog,           # parent, deleted last
]


def clear_logs():
    db = SessionLocal()
    total = 0
    try:
        for model in DELETE_ORDER:
            deleted = db.query(model).delete(synchronize_session=False)
            total += deleted
            print(f"  cleared {deleted:>6} rows from {model.__tablename__}")
        db.commit()
        print(f"\n[OK] Cleared {total} log rows. Users and hospital assets kept.")
    except Exception as error:
        db.rollback()
        print(f"[ERROR] Failed to clear logs: {error}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    print("[ICDS-H] Clearing old logs / attack history...")
    clear_logs()
