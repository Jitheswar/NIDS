from sqlalchemy import Column, BigInteger, String, DateTime, Enum, JSON, func

from database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, server_default=func.now(), index=True)
    event_type = Column(String(50), nullable=False, index=True)
    actor_id = Column(String(255), nullable=True)
    actor_type = Column(
        Enum("user", "sensor", "system", name="actor_type"),
        nullable=False,
    )
    ip_address = Column(String(45), nullable=False)  # IPv4 or IPv6
    details = Column(JSON, nullable=True)
