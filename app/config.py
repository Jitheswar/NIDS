from typing import Literal
from urllib.parse import quote_plus

from pydantic import SecretStr
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Application
    app_name: str = "NIDS"
    environment: Literal["development", "staging", "production"] = "development"
    debug: bool = False

    # Database (MariaDB)
    db_host: str = "mariadb"
    db_port: int = 3306
    db_name: str = "nids"
    db_user: str = "nids"
    db_password: SecretStr = SecretStr("")
    db_pool_size: int = 10
    db_max_overflow: int = 20
    db_pool_timeout: int = 30

    # Redis
    redis_url: str = "redis://redis:6379/0"

    # Keycloak
    keycloak_url: str = "http://keycloak:8080"
    keycloak_realm: str = "nids"
    keycloak_client_id: str = "nids-api"
    keycloak_client_secret: SecretStr = SecretStr("")
    keycloak_admin_user: str = "admin"
    keycloak_admin_password: SecretStr = SecretStr("")

    # Session
    session_idle_timeout: int = 900  # 15 minutes
    session_absolute_timeout: int = 28800  # 8 hours
    session_max_concurrent: int = 2

    # Lockout
    lockout_threshold: int = 5
    lockout_duration: int = 900  # 15 minutes
    permanent_lock_threshold: int = 20
    permanent_lock_window: int = 86400  # 24 hours

    # Sensor API Keys
    api_key_expiry: int = 3600  # 1 hour
    api_key_length: int = 32  # 256-bit

    # CORS
    cors_origins: str = "http://localhost:3000"

    # step-ca (Phase 2: mTLS)
    step_ca_url: str = "https://step-ca:9000"
    step_ca_provisioner: str = "nids-provisioner"
    step_ca_password: SecretStr = SecretStr("")
    step_ca_fingerprint: str = ""
    mtls_enabled: bool = False
    cert_validity_days: int = 30
    crl_refresh_interval: int = 60  # seconds

    # Loki (Phase 2: Audit Logging)
    loki_url: str = "http://loki:3100"

    # JWT Revocation
    jwt_revocation_prefix: str = "revoked_jwt:"

    # Phase 3: Anomaly Detection
    anomaly_detection_enabled: bool = True
    anomaly_window: int = 3600  # 1 hour sliding window
    anomaly_failed_login_threshold: int = 10  # unusual if > 10 different users fail from same IP
    anomaly_geo_hop_enabled: bool = True  # detect impossible travel
    anomaly_off_hours_start: int = 22  # 10 PM
    anomaly_off_hours_end: int = 6  # 6 AM
    anomaly_alert_prefix: str = "anomaly:"

    # Phase 3: ZTNA
    ztna_enabled: bool = False
    ztna_require_device_id: bool = False
    ztna_allowed_user_agents: str = ""  # comma-separated, empty = allow all
    ztna_geo_allowlist: str = ""  # comma-separated country codes, empty = allow all
    ztna_risk_score_threshold: int = 70  # 0-100, block if risk >= this

    # Phase 3: Rotation Health Checks
    rotation_check_interval: int = 3600  # seconds
    cert_expiry_warning_days: int = 7
    secret_max_age_days: int = 90

    # Phase 3: Infisical
    infisical_url: str = "http://infisical:8080"
    infisical_token: str = ""

    @property
    def database_url(self) -> str:
        password = quote_plus(self.db_password.get_secret_value())
        return f"mysql+pymysql://{self.db_user}:{password}@{self.db_host}:{self.db_port}/{self.db_name}"

    @property
    def async_database_url(self) -> str:
        password = quote_plus(self.db_password.get_secret_value())
        return f"mysql+aiomysql://{self.db_user}:{password}@{self.db_host}:{self.db_port}/{self.db_name}"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    model_config = {"env_file": ".env", "case_sensitive": False}


settings = Settings()
