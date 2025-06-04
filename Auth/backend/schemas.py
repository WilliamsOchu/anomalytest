# schemas.py
from pydantic import BaseModel, EmailStr
from typing import Optional


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    #username: str | None = None
    email: str | None = None


class UserCreate(BaseModel):
    #username: str
    email: str
    password: str

class UserResponse(BaseModel):
    #username: str
    id: str
    email: str | None = None

class UserInDB(UserResponse):
    hashed_password: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    email: EmailStr # To identify the user along with the token
    token: str      # The OTP or the unique string from the reset link
    new_password: str

