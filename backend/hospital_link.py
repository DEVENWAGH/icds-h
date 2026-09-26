"""Attach every detected attack to a hospital asset.

Impact lines look like:
Ransomware detected → EMR Server (A001) → High Risk
"""

from sqlalchemy import event
from sqlalchemy.orm import Session

import models

ATTACK_ASSET_CODE = {
    "Ransomware": "A001",
    "Backdoor": "A001",
    "Injection": "A005",
    "XSS": "A005",
    "Phishing": "A005",
    "Password Attack": "A006",
    "Insider Threat": "A001",
    "DDoS": "A006",
    "DoS": "A004",
    "Scanning": "A006",
    "Port Scan": "A006",
    "MITM": "A006",
    "Brute Force": "A006",
    "SQL Injection": "A001",
    "Anomaly (Zero-Day)": "A004",
}

RISK_WORD = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
}


def risk_word(severity):
    return RISK_WORD.get((severity or "HIGH").upper(), "High")


def format_impact(attack_type, asset, severity):
    code = asset.asset_code or f"A{asset.id:03d}"
    name = asset.asset_name or "Hospital Asset"
    return f"{attack_type} detected → {name} ({code}) → {risk_word(severity)} Risk"


def resolve_asset(session, attack_log):
    if attack_log.dest_ip:
        match = (
            session.query(models.HospitalAsset)
            .filter(models.HospitalAsset.ip_address == attack_log.dest_ip)
            .first()
        )
        if match:
            return match
    code = ATTACK_ASSET_CODE.get(attack_log.attack_type or "", "A001")
    return (
        session.query(models.HospitalAsset)
        .filter(models.HospitalAsset.asset_code == code)
        .first()
    )


def apply_asset_link(session, attack_log):
    if not attack_log or not attack_log.attack_type or attack_log.attack_type == "Normal":
        return None
    asset = None
    if attack_log.asset_id:
        asset = session.get(models.HospitalAsset, attack_log.asset_id)
    if asset is None:
        asset = resolve_asset(session, attack_log)
    if asset is None:
        return None
    attack_log.asset_id = asset.id
    if not attack_log.dest_ip:
        attack_log.dest_ip = asset.ip_address
    if not attack_log.impact_line:
        attack_log.impact_line = format_impact(
            attack_log.attack_type, asset, attack_log.severity
        )
    return asset


@event.listens_for(Session, "before_flush")
def link_new_attacks(session, flush_context, instances):
    pending = [
        obj
        for obj in session.new
        if isinstance(obj, models.AttackLog)
    ]
    if not pending:
        return
    with session.no_autoflush:
        for attack_log in pending:
            apply_asset_link(session, attack_log)
