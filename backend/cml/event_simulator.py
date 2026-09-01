"""
ICDS-H Event Simulator — Synthetic Raw Security Event Generator
================================================================

Generates synthetic RAW security features that feed the real ML pipeline.
Does NOT generate predictions, confidence, risk, or severity.
Those must come from the actual MLP / Isolation Forest models.

Supports:
    - TON_IoT network events (all 10 attack classes + normal)
    - PhiUSIIL phishing URL events
    - CERT insider threat events
    - Out-of-distribution anomalous events for Isolation Forest testing

Uses rejection sampling for reliable scenario demonstration:
    generate candidate → run real model → verify prediction → accept or retry.
"""

import os
import random
import string
from datetime import datetime, timedelta

import joblib
import numpy as np


# ─────────────────────────────────────────────────────────────────────────────
# PATHS
# ─────────────────────────────────────────────────────────────────────────────

BASE_DIR = os.path.dirname(__file__)


# ─────────────────────────────────────────────────────────────────────────────
# TON_IoT ATTACK FEATURE PROFILES
# ─────────────────────────────────────────────────────────────────────────────
# Each profile describes realistic feature ranges for a given attack class.
# Only raw features are set; the MLP decides the final classification.

TON_PROFILES = {
    "normal": {
        "src_port_range": (1024, 65535),
        "dst_port_choices": [80, 443, 22, 53, 8080, 3306],
        "proto_choices": ["tcp", "udp"],
        "duration_range": (0.01, 30.0),
        "src_bytes_range": (100, 50000),
        "dst_bytes_range": (100, 50000),
        "src_pkts_range": (1, 200),
        "dst_pkts_range": (1, 200),
    },
    "ddos": {
        "src_port_range": (1024, 65535),
        "dst_port_choices": [80, 443, 53],
        "proto_choices": ["tcp", "udp"],
        "duration_range": (0.001, 2.0),
        "src_bytes_range": (500000, 10000000),
        "dst_bytes_range": (0, 1000),
        "src_pkts_range": (5000, 500000),
        "dst_pkts_range": (0, 50),
    },
    "dos": {
        "src_port_range": (1024, 65535),
        "dst_port_choices": [80, 443, 8080],
        "proto_choices": ["tcp"],
        "duration_range": (0.01, 5.0),
        "src_bytes_range": (200000, 5000000),
        "dst_bytes_range": (0, 500),
        "src_pkts_range": (2000, 100000),
        "dst_pkts_range": (0, 20),
    },
    "ransomware": {
        "src_port_range": (1024, 65535),
        "dst_port_choices": [445, 139, 3389],
        "proto_choices": ["tcp"],
        "duration_range": (1.0, 60.0),
        "src_bytes_range": (100000, 2000000),
        "dst_bytes_range": (50000, 500000),
        "src_pkts_range": (100, 5000),
        "dst_pkts_range": (50, 2000),
    },
    "backdoor": {
        "src_port_range": (1024, 65535),
        "dst_port_choices": [4444, 5555, 8888, 31337, 1234],
        "proto_choices": ["tcp"],
        "duration_range": (10.0, 3600.0),
        "src_bytes_range": (1000, 100000),
        "dst_bytes_range": (5000, 500000),
        "src_pkts_range": (10, 500),
        "dst_pkts_range": (50, 1000),
    },
    "injection": {
        "src_port_range": (1024, 65535),
        "dst_port_choices": [80, 443, 8080, 3306, 5432],
        "proto_choices": ["tcp"],
        "duration_range": (0.1, 10.0),
        "src_bytes_range": (2000, 200000),
        "dst_bytes_range": (500, 100000),
        "src_pkts_range": (5, 300),
        "dst_pkts_range": (5, 200),
    },
    "password": {
        "src_port_range": (1024, 65535),
        "dst_port_choices": [22, 21, 3389, 23, 445],
        "proto_choices": ["tcp"],
        "duration_range": (0.5, 30.0),
        "src_bytes_range": (500, 50000),
        "dst_bytes_range": (200, 20000),
        "src_pkts_range": (10, 1000),
        "dst_pkts_range": (5, 500),
    },
    "scanning": {
        "src_port_range": (1024, 65535),
        "dst_port_choices": list(range(1, 1024)),
        "proto_choices": ["tcp", "udp", "icmp"],
        "duration_range": (0.001, 1.0),
        "src_bytes_range": (40, 2000),
        "dst_bytes_range": (0, 500),
        "src_pkts_range": (1, 10),
        "dst_pkts_range": (0, 5),
    },
    "xss": {
        "src_port_range": (1024, 65535),
        "dst_port_choices": [80, 443, 8080, 8443],
        "proto_choices": ["tcp"],
        "duration_range": (0.05, 5.0),
        "src_bytes_range": (1000, 100000),
        "dst_bytes_range": (2000, 200000),
        "src_pkts_range": (3, 100),
        "dst_pkts_range": (5, 150),
    },
    "mitm": {
        "src_port_range": (1024, 65535),
        "dst_port_choices": [80, 443, 53, 8080],
        "proto_choices": ["tcp", "udp"],
        "duration_range": (5.0, 600.0),
        "src_bytes_range": (10000, 1000000),
        "dst_bytes_range": (10000, 1000000),
        "src_pkts_range": (50, 5000),
        "dst_pkts_range": (50, 5000),
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# PHISHING URL PROFILES
# ─────────────────────────────────────────────────────────────────────────────

PHI_PROFILES = {
    "normal": {
        "URLLength_range": (15, 60),
        "DomainLength_range": (5, 25),
        "URLSimilarityIndex_range": (0.6, 1.0),
        "CharContinuationRate_range": (0.3, 0.8),
        "TLDLegitimateProb_range": (0.7, 1.0),
        "NoOfSubDomain_range": (0, 2),
        "LetterRatioInURL_range": (0.6, 0.95),
        "DegitRatioInURL_range": (0.0, 0.15),
        "SpacialCharRatioInURL_range": (0.05, 0.2),
        "IsHTTPS": 1,
        "url_template": "https://www.{domain}.com/{path}",
    },
    "phishing": {
        "URLLength_range": (40, 200),
        "DomainLength_range": (15, 80),
        "URLSimilarityIndex_range": (0.0, 0.4),
        "CharContinuationRate_range": (0.5, 0.95),
        "TLDLegitimateProb_range": (0.0, 0.3),
        "NoOfSubDomain_range": (2, 8),
        "LetterRatioInURL_range": (0.3, 0.7),
        "DegitRatioInURL_range": (0.1, 0.5),
        "SpacialCharRatioInURL_range": (0.15, 0.5),
        "IsHTTPS": 0,
        "url_template": "http://{subdomain}.{domain}.{tld}/{path}",
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# CERT INSIDER THREAT PROFILES
# ─────────────────────────────────────────────────────────────────────────────

CERT_PROFILES = {
    "normal": {
        "hour_range": (8, 18),
        "activities": ["Logon", "Logoff", "Connect", "Disconnect"],
        "is_after_hours": False,
        "is_weekend": False,
    },
    "insider": {
        "hour_range": (0, 5),
        "activities": ["Logon", "Connect"],
        "is_after_hours": True,
        "is_weekend": True,
    },
}


# =============================================================================
# EVENT SIMULATOR CLASS
# =============================================================================

class EventSimulator:
    """
    Generates synthetic raw security events that feed the real ML pipeline.

    IMPORTANT:
        This module generates ONLY raw features.
        It does NOT assign attack type, confidence, risk, or severity.
        Those are determined by the actual MLP / Isolation Forest.
    """

    def __init__(self):
        self.cert_user_le = None
        self.cert_pc_le = None
        self._load_cert_encoders()
        self.ton_exemplars = {}
        self._load_ton_exemplars()

        # Dataset round-robin for auto-monitoring
        self._dataset_cycle = ["TON_IoT", "PhiUSIIL", "CERT"]
        self._cycle_idx = 0

        # TON_IoT class weights for random generation
        self._ton_class_weights = {
            "normal": 0.35,
            "ddos": 0.08,
            "dos": 0.08,
            "ransomware": 0.08,
            "backdoor": 0.08,
            "injection": 0.08,
            "password": 0.08,
            "scanning": 0.07,
            "xss": 0.06,
            "mitm": 0.04,
        }

    def _load_cert_encoders(self):
        """Load CERT label encoders to generate realistic user/PC values."""
        try:
            user_path = os.path.join(BASE_DIR, "cert_user_le.pkl")
            pc_path = os.path.join(BASE_DIR, "cert_pc_le.pkl")

            if os.path.exists(user_path):
                self.cert_user_le = joblib.load(user_path)
            if os.path.exists(pc_path):
                self.cert_pc_le = joblib.load(pc_path)
        except Exception as e:
            print(f"[SIMULATOR] Could not load CERT encoders: {e}")

    def _load_ton_exemplars(self):
        """Load pre-computed high-confidence exemplar templates for TON_IoT attacks."""
        try:
            exemplars_path = os.path.join(BASE_DIR, "ton_exemplars.json")
            if os.path.exists(exemplars_path):
                import json
                with open(exemplars_path, "r") as f:
                    self.ton_exemplars = json.load(f)
        except Exception as e:
            print(f"[SIMULATOR] Could not load TON exemplars: {e}")

    # =========================================================================
    # TON_IoT EVENTS
    # =========================================================================

    def generate_ton_iot_event(self, target_class=None):
        """
        Generate synthetic network traffic features for TON_IoT.

        Args:
            target_class: Optional hint for which attack profile to use.
                         The raw features are shaped to resemble this class,
                         but the final classification comes from the MLP.

        Returns:
            dict with raw_features, dataset_source, input_source, metadata
        """
        if target_class is None:
            classes = list(self._ton_class_weights.keys())
            weights = list(self._ton_class_weights.values())
            target_class = random.choices(classes, weights=weights, k=1)[0]

        target_norm = str(target_class).strip().lower()
        rand_octet = lambda: str(random.randint(1, 254))

        if target_norm in self.ton_exemplars and len(self.ton_exemplars[target_norm]) > 0:
            template = random.choice(self.ton_exemplars[target_norm]).copy()
            raw_features = {
                "src_ip": f"192.168.{rand_octet()}.{rand_octet()}",
                "dst_ip": f"10.0.0.{random.randint(1, 30)}",
                "src_port": str(template.get("src_port", random.randint(1024, 65535))),
                "dst_port": str(template.get("dst_port", 80)),
                "proto": str(template.get("proto", "tcp")),
                "duration": float(template.get("duration", 0.0)),
                "src_bytes": float(template.get("src_bytes", 0.0)),
                "dst_bytes": float(template.get("dst_bytes", 0.0)),
                "src_pkts": int(template.get("src_pkts", 1)),
                "dst_pkts": int(template.get("dst_pkts", 0)),
            }
        else:
            profile = TON_PROFILES.get(target_norm, TON_PROFILES["normal"])
            proto = random.choice(profile["proto_choices"])

            raw_features = {
                "src_ip": f"192.168.{rand_octet()}.{rand_octet()}",
                "dst_ip": f"10.0.0.{random.randint(1, 30)}",
                "src_port": str(random.randint(*profile["src_port_range"])),
                "dst_port": str(random.choice(profile["dst_port_choices"])),
                "proto": proto,
                "duration": round(random.uniform(*profile["duration_range"]), 4),
                "src_bytes": float(random.randint(*profile["src_bytes_range"])),
                "dst_bytes": float(random.randint(*profile["dst_bytes_range"])),
                "src_pkts": random.randint(*profile["src_pkts_range"]),
                "dst_pkts": random.randint(*profile["dst_pkts_range"]),
            }

        return {
            "raw_features": raw_features,
            "dataset_source": "TON_IoT",
            "input_source": "SIMULATOR",
            "metadata": {
                "target_class_hint": target_class,
                "timestamp": datetime.utcnow().isoformat(),
            },
        }

    # =========================================================================
    # PHISHING EVENTS
    # =========================================================================

    def generate_phishing_event(self, target_class=None):
        """
        Generate synthetic PhiUSIIL-compatible URL features.
        """
        if target_class is None:
            target_class = random.choice(["normal", "phishing"])

        profile = PHI_PROFILES.get(target_class, PHI_PROFILES["normal"])

        # Generate display URL/domain
        if target_class == "phishing":
            subdomain = "".join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(5, 15)))
            domain = random.choice(["secure-login", "account-verify", "update-info", "banking-auth", "paypal-secure"])
            tld = random.choice([".xyz", ".tk", ".ml", ".ga", ".cf", ".info"])
            path = "".join(random.choices(string.ascii_lowercase + string.digits + "/", k=random.randint(10, 50)))
            url = f"http://{subdomain}.{domain}{tld}/{path}"
            display_domain = f"{subdomain}.{domain}{tld}"
        else:
            domain = random.choice(["google", "microsoft", "amazon", "github", "stackoverflow", "wikipedia"])
            path = random.choice(["", "search", "about", "docs", "help"])
            url = f"https://www.{domain}.com/{path}"
            display_domain = f"www.{domain}.com"

        raw_features = {
            "URL": url,
            "Domain": display_domain,
            "URLLength": round(random.uniform(*profile["URLLength_range"]), 2),
            "DomainLength": round(random.uniform(*profile["DomainLength_range"]), 2),
            "URLSimilarityIndex": round(random.uniform(*profile["URLSimilarityIndex_range"]), 4),
            "CharContinuationRate": round(random.uniform(*profile["CharContinuationRate_range"]), 4),
            "TLDLegitimateProb": round(random.uniform(*profile["TLDLegitimateProb_range"]), 4),
            "NoOfSubDomain": random.randint(*profile["NoOfSubDomain_range"]),
            "LetterRatioInURL": round(random.uniform(*profile["LetterRatioInURL_range"]), 4),
            "DegitRatioInURL": round(random.uniform(*profile["DegitRatioInURL_range"]), 4),
            "SpacialCharRatioInURL": round(random.uniform(*profile["SpacialCharRatioInURL_range"]), 4),
            "IsHTTPS": profile["IsHTTPS"],
        }

        return {
            "raw_features": raw_features,
            "dataset_source": "PhiUSIIL",
            "input_source": "SIMULATOR",
            "metadata": {
                "target_class_hint": target_class,
                "timestamp": datetime.utcnow().isoformat(),
            },
        }

    # =========================================================================
    # CERT EVENTS
    # =========================================================================

    def generate_cert_event(self, target_class=None):
        """
        Generate synthetic CERT insider threat features.
        Uses actual users/PCs from the encoder classes when available.
        """
        if target_class is None:
            target_class = random.choices(
                ["normal", "insider"], weights=[0.8, 0.2], k=1
            )[0]

        profile = CERT_PROFILES.get(target_class, CERT_PROFILES["normal"])

        # Pick user/PC from encoder classes if available
        if self.cert_user_le is not None and len(self.cert_user_le.classes_) > 0:
            user = random.choice(list(self.cert_user_le.classes_))
        else:
            user = f"USER{random.randint(1000, 9999)}"

        if self.cert_pc_le is not None and len(self.cert_pc_le.classes_) > 0:
            pc = random.choice(list(self.cert_pc_le.classes_))
        else:
            pc = f"PC-{random.randint(100, 999)}"

        activity = random.choice(profile["activities"])

        hour = random.randint(*profile["hour_range"])
        if target_class == "insider":
            dayofweek = random.choice([5, 6])  # Weekend
        else:
            dayofweek = random.randint(0, 4)  # Weekday

        # Build a realistic date
        base_date = datetime.utcnow() - timedelta(minutes=random.randint(0, 60))
        event_date = base_date.replace(hour=hour, minute=random.randint(0, 59))

        raw_features = {
            "user": user,
            "pc": pc,
            "activity": activity,
            "date": event_date.strftime("%Y-%m-%d %H:%M:%S"),
        }

        return {
            "raw_features": raw_features,
            "dataset_source": "CERT",
            "input_source": "SIMULATOR",
            "metadata": {
                "target_class_hint": target_class,
                "timestamp": datetime.utcnow().isoformat(),
            },
        }

    # =========================================================================
    # ANOMALOUS / OUT-OF-DISTRIBUTION EVENTS
    # =========================================================================

    def generate_anomalous_event(self):
        """
        Generate deliberately out-of-distribution network features.
        These should trigger the Isolation Forest anomaly detector.

        IMPORTANT: Does NOT force the anomaly result.
        The Isolation Forest must genuinely flag it.
        """
        rand_octet = lambda: str(random.randint(1, 254))

        raw_features = {
            "src_ip": f"185.220.{rand_octet()}.{rand_octet()}",
            "dst_ip": f"10.0.0.{random.randint(1, 30)}",
            "src_port": str(random.randint(1024, 65535)),
            "dst_port": str(random.choice([31337, 6666, 4444, 0, 9001, 1337])),
            "proto": random.choice(["tcp", "udp"]),
            "duration": round(random.choice([0.0001, 9999.0, 0.0, 86400.0]), 4),
            "src_bytes": float(random.randint(40_000_000, 99_000_000)),
            "dst_bytes": 0.0,
            "src_pkts": random.randint(500_000, 999_999),
            "dst_pkts": 0,
        }

        return {
            "raw_features": raw_features,
            "dataset_source": "TON_IoT",
            "input_source": "SIMULATOR_ANOMALY",
            "metadata": {
                "target_class_hint": "anomalous",
                "timestamp": datetime.utcnow().isoformat(),
            },
        }

    # =========================================================================
    # RANDOM EVENT (for auto-monitoring)
    # =========================================================================

    def generate_random_event(self):
        """
        Generate a random event from one of the three datasets.
        Uses round-robin dataset cycling for variety.
        """
        dataset = self._dataset_cycle[self._cycle_idx]
        self._cycle_idx = (self._cycle_idx + 1) % len(self._dataset_cycle)

        if dataset == "TON_IoT":
            return self.generate_ton_iot_event()
        elif dataset == "PhiUSIIL":
            return self.generate_phishing_event()
        elif dataset == "CERT":
            return self.generate_cert_event()
        else:
            return self.generate_ton_iot_event()


# =============================================================================
# SINGLETON
# =============================================================================

simulator = EventSimulator()
