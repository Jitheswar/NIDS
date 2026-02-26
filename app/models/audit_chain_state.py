from sqlalchemy import Column, Integer, String, DateTime, func

from database import Base


class AuditChainState(Base):
    __tablename__ = "audit_chain_state"

    id = Column(Integer, primary_key=True, default=1)
    previous_hash = Column(String(64), nullable=False, default="0" * 64)
    updated_at = Column(
        DateTime,
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )
