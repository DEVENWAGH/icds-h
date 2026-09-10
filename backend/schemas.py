from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Any
from datetime import datetime

# Auth
class UserCreate(BaseModel):
    full_name: str = Field(min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    role: str = "clinical"

class UserLogin(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)

class UserAdminUpdate(BaseModel):
    is_active: Optional[bool] = None
    role: Optional[str] = None
    clearance_level: Optional[int] = Field(default=None, ge=1, le=5)

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
    attack_log_id: Optional[int] = None
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

# Prediction Input — attack_log_id may be sent in the body or as a query param
class PredictInput(BaseModel):
    attack_log_id: Optional[int] = None

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
    status: Optional[str] = "PENDING"
    rank: Optional[int] = 1
    class Config: from_attributes = True

# Recovery Action
class RecoveryActionOut(BaseModel):
    id: int
    recommendation_id: Optional[int]
    action_name: str
    action_type: str
    target_node: Optional[str]
    status: str
    progress_percent: Optional[int] = 0
    current_step: Optional[str] = None
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

# Stage & Manual Action
class StageUpdateRequest(BaseModel):
    stage: str

class DirectManualActionRequest(BaseModel):
    attack_log_id: int
    action_type: str
    title: Optional[str] = None

