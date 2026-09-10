from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str = "sqlite:///./icds_h.db"
    # Override in .env for any non-local deployment. Default is for local development only.
    SECRET_KEY: str = "icds-h-dev-only-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480
    
    # Environment and Simulation settings
    DATASET_REPLAY_MODE: bool = False
    REPLAY_INTERVAL_SECONDS: int = 4
    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:3000"

    # Live Packet Capture settings
    LIVE_CAPTURE_ENABLED: bool = False
    CAPTURE_INTERFACE: str = "Ethernet"
    CAPTURE_BPF_FILTER: str = "tcp or udp"
    CAPTURE_BATCH_SIZE: int = 10

    # Auto-Response settings (no manual approval needed when True)
    AUTO_RESPONSE_ENABLED: bool = False
    AUTO_RESPONSE_MIN_SEVERITY: str = "HIGH"

    # Admin Credentials
    ADMIN_EMAIL: str = "admin@icds-h.com"
    ADMIN_PASSWORD: str = "change_me_admin_password"
    ADMIN_NAME: str = "Dr. Aris Thorne"
    ADMIN_CLEARANCE: int = 5

    # Analyst (SOC Lead) Credentials
    ANALYST_EMAIL: str = "analyst@icds-h.com"
    ANALYST_PASSWORD: str = "change_me_analyst_password"
    ANALYST_NAME: str = "Elena Rostova"
    ANALYST_CLEARANCE: int = 3

    # Clinical (MedDirector) Credentials
    CLINICAL_EMAIL: str = "clinical@icds-h.com"
    CLINICAL_PASSWORD: str = "change_me_clinical_password"
    CLINICAL_NAME: str = "Dr. Meera Kapoor"
    CLINICAL_CLEARANCE: int = 4

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()
