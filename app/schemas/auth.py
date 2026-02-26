from pydantic import BaseModel, Field, SecretStr


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=255)
    password: SecretStr = Field(..., min_length=1)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class UserInfo(BaseModel):
    sub: str
    username: str
    email: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    roles: list[str] = []


class UnlockRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=255)
