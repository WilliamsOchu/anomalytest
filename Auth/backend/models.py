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
    login_otps = relationship("LoginOTP", back_populates="user")




class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"
    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True, index=True) # The actual OTP/unique string
    user_id = Column(Integer, ForeignKey("users.id"))
    expires_at = Column(DateTime(timezone=True))
    is_used = Column(Boolean, default=False) # To ensure tokens are single-use
    user = relationship("User", back_populates="reset_tokens")


class PendingUser(Base):
    __tablename__ = "pending_users"
    id = Column(Integer, primary_key=True, index=True)
    #username = Column(String, unique=True, index=True) # Should be unique for pending users
    email = Column(String, unique=True, index=True)     # Should be unique for pending users
    hashed_password = Column(String)
    otp = Column(String)                                # The 5-digit OTP
    otp_expires_at = Column(DateTime(timezone=True))                   # When the OTP expires


# NEW MODEL FOR LOGIN OTP
class LoginOTP(Base):
    __tablename__ = "login_otps"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    otp = Column(String)                                # The 6-digit OTP
    expires_at = Column(DateTime(timezone=True))       # When the OTP expires
    is_used = Column(Boolean, default=False)            # To ensure single-use

    user = relationship("User", back_populates="login_otps")
