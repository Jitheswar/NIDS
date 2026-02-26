import uuid

from sqlalchemy import Column, String, DateTime, Boolean, ForeignKey, func
from sqlalchemy.dialects.mysql import CHAR
from sqlalchemy.orm import relationship

from database import Base


class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(CHAR(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    sensor_id = Column(CHAR(36), ForeignKey("sensors.id", ondelete="CASCADE"), nullable=False, index=True)
    key_hash = Column(String(64), nullable=False, index=True)  # SHA-256 hex digest
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, nullable=False, default=False)
    used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    created_by = Column(String(255), nullable=False)

    sensor = relationship("Sensor", back_populates="api_keys")
