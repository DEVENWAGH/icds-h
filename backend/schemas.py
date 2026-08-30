from pydantic import BaseModel, EmailStr
from typing import Optional, List, Any
from datetime import datetime

# Auth
class UserCreate(BaseModel):
    full_name: str
    email: EmailStr
    password: str
    role: str 

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserOut(BaseModel):
    id: int
    full_name: str
    email: str
    role: str
    clearance_level: int
    is_active: bool
    class Config: from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserOut

# Attack Logs
class AttackLogOut(BaseModel):
    id: int
    attack_type: str
    source_ip: Optional[str]
    dest_ip: Optional[str]
    protocol: Optional[str]
    port: Optional[int]
    severity: str
    status: str
    suspicious_score: Optional[float] = 0.0
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    description: Optional[str]
    detected_at: datetime
    dataset_source: Optional[str] = None
    class Config: from_attributes = True

# Hospital Assets
class HospitalAssetOut(BaseModel):
    id: int
    asset_name: str
    asset_type: Optional[str]
    ip_address: Optional[str]
    criticality: str
    status: str
    class Config: from_attributes = True

# Incidents
class IncidentOut(BaseModel):
    id: int
    attack_id: Optional[int]
    status: str
    assigned_to: Optional[int]
    mitre_technique_id: Optional[str]
    mitre_technique_name: Optional[str]
    opened_at: datetime
    closed_at: Optional[datetime]
    class Config: from_attributes = True

class IncidentUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[int] = None

# Alerts
class AlertOut(BaseModel):
    id: int
    alert_type: str
    title: str
    message: str
    severity: str
    is_acknowledged: bool
    created_at: datetime
    class Config: from_attributes = True

# Risk Score
class RiskScoreOut(BaseModel):
    id: int
    score: float
    confidence: float
    model_version: Optional[str]
    prediction_label: Optional[str]
    node_id: Optional[str]
    status: str
    computed_at: datetime
    attack_log_id: Optional[int] = None
    class Config: from_attributes = True

# Prediction Input
class PredictInput(BaseModel):
    pass

class PredictOutput(BaseModel):
    risk_score: float
    confidence: float
    prediction_label: str
    status: str
    feature_importance: dict
    node_id: str

# Recommendation
class RecommendationOut(BaseModel):
    id: int
    attack_log_id: Optional[int]
    title: str
    description: Optional[str]
    action_type: Optional[str]
    confidence_score: Optional[float]
    resource_cost: Optional[str]
    latency_impact: Optional[str]
    is_approved: bool
    class Config: from_attributes = True

# Recovery Action
class RecoveryActionOut(BaseModel):
    id: int
    recommendation_id: Optional[int]
    action_name: str
    action_type: str
    target_node: Optional[str]
    status: str
    execution_log: Optional[str]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime
    class Config: from_attributes = True

# Monitoring
class MonitoringOut(BaseModel):
    id: int
    throughput_gbps: Optional[float]
    latency_ms: Optional[float]
    sys_health: Optional[float]
    node_load_avg: Optional[float]
    recorded_at: datetime
    class Config: from_attributes = True
