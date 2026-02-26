import ipaddress
from datetime import datetime

from pydantic import BaseModel, Field, field_validator


class SensorCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255, pattern=r"^[a-zA-Z0-9_-]+$")
    network_segment: str = Field(..., max_length=100)

    @field_validator("network_segment")
    @classmethod
    def validate_cidr(cls, v: str) -> str:
        try:
            network = ipaddress.ip_network(v, strict=False)
        except ValueError as exc:
            raise ValueError("Must be a valid CIDR notation (e.g. 172.28.0.0/16)")
        return str(network)


class SensorResponse(BaseModel):
    id: str
    name: str
    network_segment: str
    status: str
    activated_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
    cert_serial: str | None = None
    cert_expires_at: datetime | None = None

    model_config = {"from_attributes": True}


class SensorListResponse(BaseModel):
    sensors: list[SensorResponse]
    total: int


class SensorCertResponse(BaseModel):
    sensor_id: str
    cert_pem: str
    ca_pem: str
    expires_at: str
    serial: str


class SensorCertIssueRequest(BaseModel):
    csr_pem: str = Field(..., min_length=1)


class SensorCertRevokeRequest(BaseModel):
    reason: str = Field(default="unspecified", max_length=50)
