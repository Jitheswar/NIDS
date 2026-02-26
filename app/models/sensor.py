import uuid

from sqlalchemy import Column, String, DateTime, Enum, Integer, func
from sqlalchemy.dialects.mysql import CHAR
from sqlalchemy.orm import relationship

from database import Base


class Sensor(Base):
    __tablename__ = "sensors"

    id = Column(CHAR(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False, unique=True, index=True)
    network_segment = Column(String(100), nullable=False)
    status = Column(
        Enum("pending", "active", "disabled", name="sensor_status"),
        nullable=False,
        default="pending",
    )
    activated_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(
        DateTime, nullable=False, server_default=func.now(), onupdate=func.now()
    )
    created_by = Column(String(255), nullable=False)

    # Phase 2: mTLS certificate tracking
    cert_serial = Column(String(128), nullable=True, index=True)
    cert_expires_at = Column(DateTime, nullable=True)
    cert_issued_at = Column(DateTime, nullable=True)
    health_check_failures = Column(Integer, nullable=False, default=0)  # Counter for auto-revocation

    api_keys = relationship("ApiKey", back_populates="sensor", cascade="all, delete-orphan")
