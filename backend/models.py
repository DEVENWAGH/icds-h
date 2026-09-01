from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, Enum, ForeignKey, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String(100))
    email = Column(String(150), unique=True, index=True)
    hashed_password = Column(String(255))
    role = Column(Enum('admin', 'analyst', 'clinical'), default='analyst')
    is_active = Column(Boolean, default=True)
    clearance_level = Column(Integer, default=1)
    last_login = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now())

class HospitalAsset(Base):
    __tablename__ = "hospital_assets"
    id = Column(Integer, primary_key=True, index=True)
    asset_name = Column(String(100), nullable=False)
    asset_type = Column(String(100))
    ip_address = Column(String(45))
    criticality = Column(Enum('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'))
    status = Column(Enum('ONLINE', 'OFFLINE', 'ISOLATED', 'COMPROMISED'), default='ONLINE')
    created_at = Column(DateTime, server_default=func.now())

class AttackLog(Base):
    __tablename__ = "attack_logs"
    id = Column(Integer, primary_key=True, index=True)
    attack_type = Column(String(100))
    source_ip = Column(String(45))
    dest_ip = Column(String(45))
    protocol = Column(String(20))
    port = Column(Integer)
    severity = Column(Enum('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'))
    status = Column(Enum('DETECTED', 'ANALYZING', 'CONTAINMENT', 'RECOVERY', 'RESOLVED'), default='DETECTED')
    suspicious_score = Column(Float, default=0.0)
    mitre_technique_id = Column(String(50), nullable=True)
    mitre_technique_name = Column(String(150), nullable=True)
    raw_features = Column(JSON, nullable=True)
    description = Column(Text, nullable=True)
    # Extended behavioral features
    cpu_utilization = Column(Float, nullable=True)
    failed_login_count = Column(Integer, nullable=True)
    malware_indicator = Column(Boolean, default=False)
    access_pattern_score = Column(Float, nullable=True)
    user_behavior_score = Column(Float, nullable=True)
    detected_at = Column(DateTime, server_default=func.now())
    resolved_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    dataset_source = Column(String(100), nullable=True)

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, index=True)
    alert_type = Column(String(100))
    title = Column(String(255))
    message = Column(Text)
    severity = Column(Enum('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'))
    is_acknowledged = Column(Boolean, default=False)
    attack_log_id = Column(Integer, ForeignKey("attack_logs.id"), nullable=True)
    acknowledged_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    acknowledged_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now())

class RiskScore(Base):
    __tablename__ = "risk_scores"
    id = Column(Integer, primary_key=True, index=True)
    score = Column(Float)
    confidence = Column(Float)
    confidence_band = Column(String(20), nullable=True)   # Low/Medium/High/Very High
    risk_band = Column(String(20), nullable=True)         # LOW/MEDIUM/HIGH/CRITICAL
    model_version = Column(String(50), default='MLP_v5')
    features_used = Column(JSON, nullable=True)
    prediction_label = Column(String(100))
    node_id = Column(String(50))
    status = Column(Enum('STABLE', 'WARNING', 'CRITICAL'), default='STABLE')
    shap_values = Column(JSON, nullable=True)             # Cached SHAP attribution
    computed_at = Column(DateTime, server_default=func.now())
    attack_log_id = Column(Integer, ForeignKey("attack_logs.id"), nullable=True)

class Recommendation(Base):
    __tablename__ = "recommendations"
    id = Column(Integer, primary_key=True, index=True)
    attack_log_id = Column(Integer, ForeignKey("attack_logs.id"), nullable=True)
    title = Column(String(255))
    description = Column(Text)
    action_type = Column(String(100))
    confidence_score = Column(Float)
    resource_cost = Column(String(50))
    latency_impact = Column(String(50))
    is_approved = Column(Boolean, default=False)
    status = Column(String(20), default='PENDING')  # PENDING, APPROVED, REJECTED
    rank = Column(Integer, default=1)
    approved_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now())

class RecoveryAction(Base):
    __tablename__ = "recovery_actions"
    id = Column(Integer, primary_key=True, index=True)
    recommendation_id = Column(Integer, ForeignKey("recommendations.id"), nullable=True)
    action_name = Column(String(255))
    action_type = Column(Enum('ISOLATE', 'BLOCK', 'RESTORE', 'RESET', 'PATCH', 'WAF_RULE', 'MONITOR_ENHANCED'))
    target_node = Column(String(100))
    status = Column(Enum('PENDING', 'IN_PROGRESS', 'COMPLETED', 'FAILED'), default='PENDING')
    progress_percent = Column(Integer, default=0)
    current_step = Column(String(255), nullable=True)
    executed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    execution_log = Column(Text, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now())

class Incident(Base):
    __tablename__ = "incidents"
    id = Column(Integer, primary_key=True, index=True)
    attack_id = Column(Integer, ForeignKey("attack_logs.id"), nullable=True)
    status = Column(Enum('DETECTED', 'ANALYZING', 'CONTAINMENT', 'RECOVERY', 'RESOLVED'), default='DETECTED')
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)
    mitre_technique_id = Column(String(50), nullable=True)
    mitre_technique_name = Column(String(150), nullable=True)
    opened_at = Column(DateTime, server_default=func.now())
    closed_at = Column(DateTime, nullable=True)

class MonitoringHistory(Base):
    __tablename__ = "monitoring_history"
    id = Column(Integer, primary_key=True, index=True)
    throughput_gbps = Column(Float)
    packet_loss = Column(Float)
    latency_ms = Column(Float)
    active_connections = Column(Integer)
    node_load_avg = Column(Float)
    sys_health = Column(Float)
    mlp_model_status = Column(String(50))
    quantum_optimizer_status = Column(String(50))
    recorded_at = Column(DateTime, server_default=func.now())

# ─────────────────────────────────────────────────────────────────────────────
# NEW TABLES
# ─────────────────────────────────────────────────────────────────────────────

class QIGAResult(Base):
    """Stores results from Quantum-Inspired Genetic Algorithm optimizer runs."""
    __tablename__ = "qiga_results"
    id = Column(Integer, primary_key=True, index=True)
    attack_log_id = Column(Integer, ForeignKey("attack_logs.id"), nullable=True)
    risk_score = Column(Float)
    attack_type = Column(String(100))
    severity = Column(String(20))
    objective_score = Column(Float)           # Minimized F value
    selected_actions = Column(JSON)           # List of chosen action IDs
    all_actions_scored = Column(JSON)         # Full scored action table
    convergence_data = Column(JSON)           # F per generation
    combined_effectiveness = Column(Float)
    combined_cost = Column(Integer)
    total_downtime_min = Column(Integer)
    alpha = Column(Float, default=0.4)        # Downtime weight
    beta = Column(Float, default=0.35)        # Data loss weight
    gamma = Column(Float, default=0.25)       # Cost weight
    generations = Column(Integer)
    population_size = Column(Integer)
    computed_at = Column(DateTime, server_default=func.now())

class AttackMemoryEntry(Base):
    """Persistent attack knowledge memory for cross-session pattern matching."""
    __tablename__ = "attack_memory"
    id = Column(Integer, primary_key=True, index=True)
    attack_log_id = Column(Integer, ForeignKey("attack_logs.id"), nullable=True)
    attack_type = Column(String(100))
    severity = Column(String(20))
    risk_score = Column(Float)
    feature_fingerprint = Column(JSON)        # Normalized feature vector
    raw_features = Column(JSON)
    recommended_actions = Column(JSON)        # List of action IDs
    outcome = Column(String(50))              # DETECTED/CONTAINMENT/RECOVERY/RESOLVED
    success = Column(Boolean, default=False)
    recorded_at = Column(DateTime, server_default=func.now())


class FirewallRule(Base):
    """Active firewall rules - blocked IPs, ports, protocols."""
    __tablename__ = "firewall_rules"
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), nullable=True, index=True)
    port = Column(Integer, nullable=True)
    protocol = Column(String(20), nullable=True)
    direction = Column(String(10), default="INBOUND")  # INBOUND / OUTBOUND / BOTH
    reason = Column(String(255), nullable=True)
    attack_type = Column(String(100), nullable=True)
    severity = Column(String(20), nullable=True)
    attack_log_id = Column(Integer, ForeignKey("attack_logs.id"), nullable=True)
    blocked_by = Column(String(100), default="SYSTEM")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, server_default=func.now())
    expires_at = Column(DateTime, nullable=True)


class AnomalyDetection(Base):
    """Stores Isolation Forest anomaly detection results per event."""
    __tablename__ = "anomaly_detections"
    id = Column(Integer, primary_key=True, index=True)
    attack_log_id = Column(Integer, ForeignKey("attack_logs.id"), nullable=True)
    anomaly_score = Column(Float)                     # Decision function output (negative = anomalous)
    is_anomaly = Column(Boolean, default=False)
    detector_type = Column(String(50), default="IsolationForest")
    dataset_source = Column(String(100), nullable=True)
    features_used = Column(JSON, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
