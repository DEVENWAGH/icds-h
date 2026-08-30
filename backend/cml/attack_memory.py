"""
ICDS-H Attack Knowledge Memory
================================
Stores historical attack fingerprints and their outcomes to improve
future decision recommendations via pattern matching.

Features:
  - Store attack event + recommended actions + outcomes
  - Find k-nearest similar attacks using Euclidean distance on dataset-specific feature vectors
  - Return historically successful response actions
  - Confidence weighting based on similarity and past success rate
"""
import numpy as np
from typing import Dict, List, Optional
from datetime import datetime


class AttackMemory:
    """
    In-memory + database-backed attack knowledge store.
    Fingerprints are stored as normalized feature vectors depending on dataset_source.
    """

    def __init__(self, max_size: int = 500):
        self.max_size = max_size
        self._memory: List[Dict] = []  # In-memory cache for fast lookup

    def add(
        self,
        attack_id: int,
        attack_type: str,
        severity: str,
        risk_score: float,
        features: Dict,
        recommended_actions: List[str],
        outcome: str = "DETECTED",   # DETECTED, CONTAINMENT, RECOVERY, RESOLVED
        success: bool = False,
        dataset_source: Optional[str] = None,
    ) -> None:
        """Store an attack fingerprint in memory."""
        dataset_source = self._infer_dataset(features, dataset_source)
        fingerprint = self._extract_fingerprint(features, dataset_source)
        entry = {
            "attack_id": attack_id,
            "attack_type": attack_type,
            "severity": severity,
            "risk_score": risk_score,
            "fingerprint": fingerprint,
            "features": features,
            "dataset_source": dataset_source,
            "recommended_actions": recommended_actions,
            "outcome": outcome,
            "success": success,
            "timestamp": datetime.utcnow().isoformat(),
        }
        self._memory.append(entry)
        # Rolling window — evict oldest
        if len(self._memory) > self.max_size:
            self._memory.pop(0)

    def find_similar(
        self,
        features: Dict,
        attack_type: Optional[str] = None,
        k: int = 5,
        dataset_source: Optional[str] = None,
    ) -> List[Dict]:
        """
        Find k-nearest historical attacks by feature similarity.
        Optionally filter by attack_type for higher relevance.
        Returns ranked list with similarity scores.
        """
        dataset_source = self._infer_dataset(features, dataset_source)

        if not self._memory:
            return []

        query_fp = self._extract_fingerprint(features, dataset_source)

        scored = []
        for entry in self._memory:
            # We must only compare within the exact same dataset schema
            if entry.get("dataset_source") != dataset_source:
                continue
                
            mem_fp = entry["fingerprint"]
            if mem_fp.shape != query_fp.shape:
                continue

            # Euclidean distance on normalized fingerprint
            dist = float(np.linalg.norm(query_fp - mem_fp))
            similarity = 1 / (1 + dist)  # Convert to similarity (0–1)
            serializable_entry = {k_item: (v_item.tolist() if isinstance(v_item, np.ndarray) else v_item) for k_item, v_item in entry.items()}
            scored.append({**serializable_entry, "similarity": round(similarity, 3)})

        # Filter by attack type if provided
        if attack_type:
            type_filtered = [s for s in scored if s["attack_type"] == attack_type]
            if len(type_filtered) >= 2:
                scored = type_filtered

        scored.sort(key=lambda x: x["similarity"], reverse=True)
        return scored[:k]

    def get_best_actions(
        self, features: Dict, attack_type: Optional[str] = None, k: int = 5, dataset_source: Optional[str] = None
    ) -> List[Dict]:
        """
        Returns recommended actions weighted by historical success rate
        for similar attacks.
        """
        similar = self.find_similar(features, attack_type, k=k, dataset_source=dataset_source)
        if not similar:
            return []

        # Aggregate action recommendations weighted by similarity × success
        action_scores: Dict[str, float] = {}
        action_counts: Dict[str, int] = {}

        for entry in similar:
            weight = entry["similarity"] * (1.5 if entry.get("success") else 0.7)
            for action in entry.get("recommended_actions", []):
                # Only keep finalized active actions
                if action in {"ISOLATE", "BLOCK", "RESTORE", "RESET", "PATCH"}:
                    action_scores[action] = action_scores.get(action, 0) + weight
                    action_counts[action] = action_counts.get(action, 0) + 1

        total = sum(action_scores.values()) or 1
        ranked = sorted([
            {
                "action": action,
                "historical_confidence": round(score / total, 3),
                "occurrence_count": action_counts[action],
                "from_memory": True,
            }
            for action, score in action_scores.items()
        ], key=lambda x: x["historical_confidence"], reverse=True)

        return ranked

    def stats(self) -> Dict:
        """Return memory statistics."""
        if not self._memory:
            return {
                "total": 0,
                "total_entries": 0,
                "capacity": self.max_size,
                "by_type": {},
                "success_rate": 0,
                "overall_success_rate": 0,
                "unique_actions": 0,
                "most_frequent_attack_type": None,
            }

        by_type: Dict[str, int] = {}
        successes = 0
        unique_actions = set()
        for e in self._memory:
            by_type[e["attack_type"]] = by_type.get(e["attack_type"], 0) + 1
            if e.get("success"):
                successes += 1
            for action in (e.get("recommended_actions") or []):
                unique_actions.add(action)

        total = len(self._memory)
        success_rate = round(successes / total, 3)
        most_frequent = max(by_type, key=by_type.get) if by_type else None

        return {
            # legacy keys (kept for backward compatibility)
            "total": total,
            "capacity": self.max_size,
            "by_type": by_type,
            "success_rate": success_rate,
            # keys consumed by the Threat Memory UI cards
            "total_entries": total,
            "overall_success_rate": success_rate,
            "unique_actions": len(unique_actions),
            "most_frequent_attack_type": most_frequent,
        }

    def _infer_dataset(self, features: Dict, explicit_source: Optional[str] = None) -> str:
        """Determine dataset source from explicit arg or safe inference."""
        if explicit_source:
            if explicit_source not in ("TON_IoT", "PhiUSIIL", "CERT"):
                raise ValueError(f"Unsupported dataset_source: {explicit_source}")
            return explicit_source

        if any(k in features for k in ("URLLength", "URLSimilarityIndex", "IsHTTPS")):
            return "PhiUSIIL"
        if any(k in features for k in ("hour", "dayofweek", "user", "activity")):
            return "CERT"
        if any(k in features for k in ("src_port", "dst_port", "src_bytes", "proto")):
            return "TON_IoT"
            
        raise ValueError("Cannot safely infer dataset_source from features, and no explicit source was provided.")

    def _safe_float(self, val, default=0.0):
        """Safely convert a value to float."""
        if val is None:
            return default
        s = str(val).strip()
        if s in ('', '-', 'N/A', 'nan', 'None'):
            return default
        try:
            return float(s)
        except (ValueError, TypeError):
            return default

    def _extract_fingerprint(self, features: Dict, dataset_source: Optional[str] = None) -> np.ndarray:
        """Extract and normalize a fixed-dimension feature vector based on dataset."""
        dataset = self._infer_dataset(features, dataset_source)

        if dataset == "TON_IoT":
            proto_map = {'tcp': 6, 'udp': 17, 'icmp': 1}
            proto_num = proto_map.get(str(features.get('proto', '')).lower(), 0)
            
            raw = np.array([
                self._safe_float(features.get("src_port")) / 65535.0,
                self._safe_float(features.get("dst_port")) / 65535.0,
                proto_num / 17.0,
                self._safe_float(features.get("duration")),
                self._safe_float(features.get("src_bytes")) / 10000.0,
                self._safe_float(features.get("dst_bytes")) / 10000.0,
                self._safe_float(features.get("src_pkts")) / 100.0,
                self._safe_float(features.get("dst_pkts")) / 100.0,
            ])
        elif dataset == "PhiUSIIL":
            raw = np.array([
                self._safe_float(features.get("URLLength")) / 100.0,
                self._safe_float(features.get("DomainLength")) / 50.0,
                self._safe_float(features.get("URLSimilarityIndex")),
                self._safe_float(features.get("CharContinuationRate")),
                self._safe_float(features.get("TLDLegitimateProb")),
                self._safe_float(features.get("NoOfSubDomain")) / 10.0,
                self._safe_float(features.get("LetterRatioInURL")),
                self._safe_float(features.get("DegitRatioInURL")),
                self._safe_float(features.get("SpacialCharRatioInURL")),
                self._safe_float(features.get("IsHTTPS"))
            ])
        else: # CERT
            hour = self._safe_float(features.get("hour"))
            dayofweek = self._safe_float(features.get("dayofweek"))
            is_after_hours = 1.0 if (hour < 6 or hour > 19) else 0.0
            is_weekend = 1.0 if dayofweek >= 5 else 0.0
            
            activity_map = {'Logon': 0, 'Logoff': 1, 'Connect': 2, 'Disconnect': 3}
            activity_str = str(features.get('activity', '')).strip()
            activity_type = float(activity_map.get(activity_str, 0)) / 3.0
            
            # For fingerprinting purposes, we just hash strings if they are present, 
            # since we don't want to rely on the trained encoders for a simple distance metric.
            # But the prompt says "string identifiers such as URL, user, and PC must not be used as meaningless raw numerical values"
            # Since distance on hashed IDs is arbitrary, we will just use binary 'has_user' / 'has_pc' or ignore them.
            # We will use 0.0 for them to avoid arbitrary distances.
            raw = np.array([
                hour / 24.0,
                dayofweek / 7.0,
                is_after_hours,
                is_weekend,
                activity_type,
                0.0, # Ignore arbitrary string identifier
                0.0  # Ignore arbitrary string identifier
            ])

        # L2 normalize
        norm = np.linalg.norm(raw)
        return raw / norm if norm > 0 else raw

# Singleton instance
attack_memory = AttackMemory(max_size=500)
