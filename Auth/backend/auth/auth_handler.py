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
import random


import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart




from sqlalchemy.orm import Session

from ..database import get_db
from ..schemas import TokenData
from ..models import User, PasswordResetToken, PendingUser, LoginOTP

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
    return secrets.token_urlsafe(4) # Generates a 43-character string

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
    #db.add(db_token)
    db.delete(db_token)
    db.commit()
    #db.refresh(db_token)


def update_user_password(db: Session, user: User, new_password: str):
    """Hashes and updates the user's password."""
    user.hashed_password = get_password_hash(new_password)
    db.add(user)
    db.commit()
    db.refresh(user)


# --- Email Sending Function (Placeholder - Replace with production-ready code) ---
async def send_password_reset_email(email: str, reset_value: str, is_otp: bool = True):
    """
    Sends a password reset email to the user.
    
    In a real application, you would integrate with an email service (e.g., SendGrid, Mailgun)
    or use Python's smtplib with proper configuration from environment variables.
    """
    # Environment variables for email configuration
    EMAIL_SENDER = os.getenv("EMAIL_SENDER")
    EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD") # Use an app password if using Gmail/Outlook
    SMTP_SERVER = os.getenv("SMTP_SERVER")
    SMTP_PORT = int(os.getenv("SMTP_PORT", 587)) # Default to 587 for TLS

    if not EMAIL_SENDER or not EMAIL_PASSWORD or not SMTP_SERVER:
        print("\n--- WARNING: Email sending configuration missing. SIMULATING EMAIL SEND ---")
        print("Please set EMAIL_SENDER, EMAIL_PASSWORD, SMTP_SERVER in your .env file.")
        # Proceed to print email content for demonstration
    else:
        print(f"\n--- ATTEMPTING TO SEND REAL EMAIL TO: {email} ---")
        # Actual email sending logic using smtplib
        msg = MIMEMultipart()
        msg['From'] = EMAIL_SENDER
        msg['To'] = email
        if is_otp:
            msg['Subject'] = "Your Password Reset OTP"
            body = (
                f"Hello,\n\nYour One-Time Password (OTP) for password reset is: {reset_value}\n\n"
                f"This OTP is valid for {PASSWORD_RESET_TOKEN_EXPIRE_MINUTES} minutes.\n\n"
                "If you did not request this, please ignore this email.\n\n"
                "Thanks,\nYour App Team"
            )
        else:
            msg['Subject'] = "Your Password Reset Link"
            body = (
                f"Hello,\n\nPlease click the following link to reset your password:\n\n"
                f"{reset_value}\n\n" # reset_value is the full URL here
                f"This link is valid for {PASSWORD_RESET_TOKEN_EXPIRE_MINUTES} minutes.\n\n"
                "If you did not request this, please ignore this email.\n\n"
                "Thanks,\nYour App Team"
            )
        msg.attach(MIMEText(body, 'plain'))

        try:
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls() # Secure the connection
                server.login(EMAIL_SENDER, EMAIL_PASSWORD)
                server.send_message(msg)
            print(f"Email sent successfully to {email}")
            return True
        except Exception as e:
            print(f"Error sending email to {email}: {e}")
            print(f"SIMULATED EMAIL CONTENT:")
            # Fallback to printing if real email fails
            pass # Continue to print simulated content

    # Always print simulated content for demonstration
    print(f"\n--- SIMULATED EMAIL TO: {email} ---")
    if is_otp:
        print(f"Subject: Your Password Reset OTP")
        print(f"Body: Hello,\n\nYour One-Time Password (OTP) for password reset is: {reset_value}")
        print(f"This OTP is valid for {PASSWORD_RESET_TOKEN_EXPIRE_MINUTES} minutes.")
        print(f"If you did not request this, please ignore this email.")
    else:
        print(f"Subject: Your Password Reset Link")
        print(f"Body: Hello,\n\nPlease click the following link to reset your password:")
        print(f"Link: {reset_value}")
        print(f"This link is valid for {PASSWORD_RESET_TOKEN_EXPIRE_MINUTES} minutes.")
        print(f"If you did not request this, please ignore this email.")
    print("-----------------------------------\n")
    return False # Return False if email sending was simulated or failed


# --- NEW EMAIL VERIFICATION OTP LOGIC ---

EMAIL_VERIFICATION_OTP_EXPIRE_MINUTES = 5 # OTP validity for email verification

def generate_five_digit_otp():
    """Generates a random 5-digit OTP."""
    return str(random.randint(100000, 999999))

def save_pending_user_registration(db: Session, email: str, hashed_password: str, otp: str):
    """Saves temporary user registration data with an OTP."""
    otp_expires_at = datetime.now(timezone.utc) + timedelta(minutes=EMAIL_VERIFICATION_OTP_EXPIRE_MINUTES)
    pending_user = PendingUser(
        email=email,
        hashed_password=hashed_password,
        otp=otp,
        otp_expires_at=otp_expires_at
    )
    db.add(pending_user)
    db.commit()
    db.refresh(pending_user)
    return pending_user

def get_pending_user_by_email(db: Session, email: str):
    """
    Retrieves a pending user by email, ensuring the OTP is not expired.
    """
    now = datetime.now(timezone.utc)
    return db.query(PendingUser).filter(
        PendingUser.email == email,
        PendingUser.otp_expires_at > now
    ).first()

def delete_pending_user(db: Session, pending_user_record: PendingUser):
    """Deletes a pending user record after successful verification or expiry."""
    db.delete(pending_user_record)
    db.commit()

async def send_verification_otp_email(email: str, otp: str):
    """
    Sends the 5-digit OTP to the user's email for verification.
    """
    EMAIL_SENDER = os.getenv("EMAIL_SENDER")
    EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD") # Use an app password if using Gmail/Outlook
    SMTP_SERVER = os.getenv("SMTP_SERVER")
    SMTP_PORT = int(os.getenv("SMTP_PORT", 587)) # Default to 587 for TLS

    if not EMAIL_SENDER or not EMAIL_PASSWORD or not SMTP_SERVER:
        print("\n--- WARNING: Email sending configuration missing. SIMULATING EMAIL SEND ---")
        print("Please set EMAIL_SENDER, EMAIL_PASSWORD, SMTP_SERVER in your .env file.")
        # Fallback to printing if configuration is missing
        print(f"\n--- SIMULATED VERIFICATION EMAIL TO: {email} ---")
        print(f"Subject: Verify Your Email for Registration")
        print(f"Body: Your 5-digit One-Time Password (OTP) for email verification is: {otp}\n")
        print(f"This OTP is valid for {EMAIL_VERIFICATION_OTP_EXPIRE_MINUTES} minutes.")
        print("-----------------------------------\n")
        return False # Indicate simulated/failed send
    else:
        print(f"\n--- ATTEMPTING TO SEND REAL EMAIL TO: {email} ---")
        msg = MIMEMultipart()
        msg['From'] = EMAIL_SENDER
        msg['To'] = email
        msg['Subject'] = "Verify Your Email for Registration"
        body = (
            f"Hello,\n\nYour 5-digit One-Time Password (OTP) for email verification is: {otp}\n\n"
            f"This OTP is valid for {EMAIL_VERIFICATION_OTP_EXPIRE_MINUTES} minutes.\n\n"
            "Please enter this code on the registration verification page to complete your signup.\n\n"
            "If you did not attempt to register, please ignore this email.\n\n"
            "Thanks,\nYour App Team"
        )
        msg.attach(MIMEText(body, 'plain'))

        try:
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls() # Secure the connection
                server.login(EMAIL_SENDER, EMAIL_PASSWORD)
                server.send_message(msg)
            print(f"Verification OTP email sent successfully to {email}")
            return True
        except Exception as e:
            print(f"Error sending verification OTP email to {email}: {e}")
            print(f"SIMULATED EMAIL CONTENT DUE TO ERROR:")
            print(f"\n--- SIMULATED VERIFICATION EMAIL TO: {email} ---")
            print(f"Subject: Verify Your Email for Registration")
            print(f"Body: Your 5-digit One-Time Password (OTP) is: {otp}\n")
            print(f"This OTP is valid for {EMAIL_VERIFICATION_OTP_EXPIRE_MINUTES} minutes.")
            print("-----------------------------------\n")
            return False # Indicate failed send
        


# --- NEW LOGIN OTP LOGIC ---

LOGIN_OTP_EXPIRE_MINUTES = 5 # OTP validity for login (e.g., 2 minutes)

def generate_six_digit_otp():
    """Generates a random 6-digit OTP."""
    return str(random.randint(100000, 999999))

def save_login_otp(db: Session, user_id: int, otp: str):
    """Saves the generated login OTP to the database with an expiry."""
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=LOGIN_OTP_EXPIRE_MINUTES)
    db_otp = LoginOTP(
        user_id=user_id,
        otp=otp,
        expires_at=expires_at,
        is_used=False
    )
    db.add(db_otp)
    db.commit()
    db.refresh(db_otp)
    return db_otp

def get_valid_login_otp(db: Session, user_id: int, otp: str):
    """Retrieves a valid, unused login OTP for a specific user."""
    now = datetime.now(timezone.utc)
    return db.query(LoginOTP).filter(
        LoginOTP.user_id == user_id,
        LoginOTP.otp == otp,
        LoginOTP.expires_at > now,
        LoginOTP.is_used == False
    ).first()

def mark_login_otp_as_used(db: Session, db_login_otp: LoginOTP):
    """Marks a login OTP as used after successful verification."""
    db_login_otp.is_used = True
    #db.add(db_login_otp)
    db.delete(db_login_otp)
    db.commit()
    #db.refresh(db_login_otp)

async def send_login_otp_email(email: str, otp: str):
    """
    Sends the 6-digit OTP to the user's email for login approval.
    """
    EMAIL_SENDER = os.getenv("EMAIL_SENDER")
    EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
    SMTP_SERVER = os.getenv("SMTP_SERVER")
    SMTP_PORT = int(os.getenv("SMTP_PORT", 587))

    if not EMAIL_SENDER or not EMAIL_PASSWORD or not SMTP_SERVER:
        print("\n--- WARNING: Email sending configuration missing. SIMULATING LOGIN OTP EMAIL SEND ---")
        print("Please set EMAIL_SENDER, EMAIL_PASSWORD, SMTP_SERVER in your .env file.")
        print(f"\n--- SIMULATED LOGIN OTP EMAIL TO: {email} ---")
        print(f"Subject: Your Login Approval OTP")
        print(f"Body: Your 6-digit One-Time Password (OTP) for login approval is: {otp}\n")
        print(f"This OTP is valid for {LOGIN_OTP_EXPIRE_MINUTES} minutes.")
        print("-----------------------------------\n")
        return False
    else:
        print(f"\n--- ATTEMPTING TO SEND REAL LOGIN OTP EMAIL TO: {email} ---")
        msg = MIMEMultipart()
        msg['From'] = EMAIL_SENDER
        msg['To'] = email
        msg['Subject'] = "Your Login Approval OTP"
        body = (
            f"Hello,\n\nYour 6-digit One-Time Password (OTP) for login approval is: {otp}\n\n"
            f"This OTP is valid for {LOGIN_OTP_EXPIRE_MINUTES} minutes.\n\n"
            "Please enter this code on the login verification page to complete your login.\n\n"
            "If you did not attempt to log in, please ignore this email.\n\n"
            "Thanks,\nYour App Team"
        )
        msg.attach(MIMEText(body, 'plain'))

        try:
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls()
                server.login(EMAIL_SENDER, EMAIL_PASSWORD)
                server.send_message(msg)
            print(f"Login OTP email sent successfully to {email}")
            return True
        except Exception as e:
            print(f"Error sending login OTP email to {email}: {e}")
            print(f"SIMULATED EMAIL CONTENT DUE TO ERROR:")
            print(f"\n--- SIMULATED LOGIN OTP EMAIL TO: {email} ---")
            print(f"Subject: Your Login Approval OTP")
            print(f"Body: Your 6-digit One-Time Password (OTP) for login approval is: {otp}\n")
            print(f"This OTP is valid for {LOGIN_OTP_EXPIRE_MINUTES} minutes.")
            print("-----------------------------------\n")
            return False