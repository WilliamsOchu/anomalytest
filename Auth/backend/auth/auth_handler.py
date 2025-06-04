## Setup Dependencies
import jwt
from fastapi import Depends, HTTPException, status, APIRouter
from fastapi.security import OAuth2PasswordBearer
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
import os
import secrets
from typing import Optional
from jose import jwt, JWTError


import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart




from sqlalchemy.orm import Session

from ..database import get_db
from ..schemas import TokenData
from ..models import User, PasswordResetToken

##Variables to encrypt password and set timer for access token expiration
load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES")


## Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Acces Token Validation 
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")

router = APIRouter()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db: Session, email: str):
    db_user = db.query(User).filter(User.email == email).first()
    return db_user


def authenticate_user(db: Session, email: str, password: str):
    user = get_user(db, email)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except InvalidTokenError:
        raise credentials_exception

    user = db.query(User).filter(User.email == token_data.email).first()
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    return current_user


PASSWORD_RESET_TOKEN_EXPIRE_MINUTES = 15

def generate_password_reset_token():
    """Generates a secure, URL-safe random string for the token."""
    return secrets.token_urlsafe(32) # Generates a 43-character string

def save_password_reset_token(db: Session, user_id: int, token: str):
    """Saves the generated token to the database with an expiry."""
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=PASSWORD_RESET_TOKEN_EXPIRE_MINUTES)
    db_token = PasswordResetToken(
        user_id=user_id,
        token=token,
        expires_at=expires_at,
        is_used=False
    )
    db.add(db_token)
    db.commit()
    db.refresh(db_token)
    return db_token


def get_password_reset_token(db: Session, token: str):
    """Retrieves a valid, unused token from the database."""
    now = datetime.now(timezone.utc)
    return db.query(PasswordResetToken).filter(
        PasswordResetToken.token == token,
        PasswordResetToken.expires_at > now,
        PasswordResetToken.is_used == False # Ensure it hasn't been used yet
    ).first()


def mark_token_as_used(db: Session, db_token: PasswordResetToken):
    """Marks a token as used after successful password reset."""
    db_token.is_used = True
    db.add(db_token)
    db.commit()
    db.refresh(db_token)


def update_user_password(db: Session, user: User, new_password: str):
    """Hashes and updates the user's password."""
    user.hashed_password = get_password_hash(new_password)
    db.add(user)
    db.commit()
    db.refresh(user)