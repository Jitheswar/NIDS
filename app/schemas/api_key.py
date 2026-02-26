from datetime import datetime

from pydantic import BaseModel, Field


class ApiKeyResponse(BaseModel):
    api_key: str = Field(..., description="The API key (shown only once)")
    sensor_id: str
    expires_at: datetime


class SensorActivateRequest(BaseModel):
    api_key: str = Field(..., min_length=1, max_length=255)


class SensorActivateResponse(BaseModel):
    sensor_id: str
    status: str
    message: str
