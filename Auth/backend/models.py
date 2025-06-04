## Setup Libraries
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

## Specify the User Data to work with
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    #username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    reset_tokens = relationship("PasswordResetToken", back_populates="user")


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"
    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True, index=True) # The actual OTP/unique string
    user_id = Column(Integer, ForeignKey("users.id"))
    expires_at = Column(DateTime)
    is_used = Column(Boolean, default=False) # To ensure tokens are single-use
    user = relationship("User", back_populates="reset_tokens")