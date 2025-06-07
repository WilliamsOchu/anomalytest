# schemas.py
import re # Import the regular expression module
from pydantic import BaseModel, EmailStr, model_validator # Import model_validator


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    #username: str | None = None
    email: EmailStr | None = None


class UserCreate(BaseModel):
    #username: str
    email: EmailStr
    password: str
    confirm_password: str

    # NEW: Pydantic validator for password complexity and match
    @model_validator(mode='after')
    def check_password_requirements(self) -> 'UserCreate':
        # 1. Check if passwords match (moved from router to schema)
        if self.password != self.confirm_password:
            raise ValueError("Passwords do not match.")

        # 2. Check password complexity requirements
        password = self.password

        # At least 12 characters long
        if len(password) < 12:
            raise ValueError("Password must be at least 12 characters long.")

        # At least one uppercase letter
        if not re.search(r"[A-Z]", password):
            raise ValueError("Password must contain at least one uppercase letter.")

        # At least one number
        if not re.search(r"[0-9]", password):
            raise ValueError("Password must contain at least one number.")

        # At least one special character
        # Define a set of common special characters. You can expand/reduce this as needed.
        special_chars_regex = r"[!@#$%^&*()_+\-=\[\]{}|;:'\",.<>/?`~]"
        if not re.search(special_chars_regex, password):
            raise ValueError("Password must contain at least one special character (e.g., !@#$%^&*).")

        return self # Return the instance if all validations pass


class UserResponse(BaseModel):
    #username: str
    id: int
    email: EmailStr | None = None

class UserInDB(UserResponse):
    hashed_password: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    email: EmailStr # To identify the user along with the token
    token: str      # The OTP or the unique string from the reset link
    new_password: str
    confirm_new_password: str


    # NEW: Pydantic validator for password complexity and match
    @model_validator(mode='after')
    def check_password_requirements_reset(self) -> 'ResetPasswordRequest':
        # 1. Check if passwords match (moved from router to schema)
        if self.new_password != self.confirm_new_password:
            raise ValueError("Passwords do not match.")

        # 2. Check password complexity requirements
        password = self.new_password

        # At least 12 characters long
        if len(password) < 12:
            raise ValueError("Password must be at least 12 characters long.")

        # At least one uppercase letter
        if not re.search(r"[A-Z]", password):
            raise ValueError("Password must contain at least one uppercase letter.")

        # At least one number
        if not re.search(r"[0-9]", password):
            raise ValueError("Password must contain at least one number.")

        # At least one special character
        # Define a set of common special characters. You can expand/reduce this as needed.
        special_chars_regex = r"[!@#$%^&*()_+\-=\[\]{}|;:'\",.<>/?`~]"
        if not re.search(special_chars_regex, password):
            raise ValueError("Password must contain at least one special character (e.g., !@#$%^&*).")

        return self # Return the instance if all validations pass


# NEW SCHEMA FOR OTP VERIFICATION
class VerifyOTPRequest(BaseModel):
    email: EmailStr
    otp: str # The 5-digit OTP entered by the user



# NEW SCHEMA FOR LOGIN OTP REQUEST (Initial login step)
class LoginOTPRequest(BaseModel):
    email: EmailStr # Assuming email is the identifier for login
    password: str

# NEW SCHEMA FOR VERIFYING LOGIN OTP (Second login step)
class VerifyLoginOTPRequest(BaseModel):
    email: EmailStr
    otp: str # The 6-digit OTP entered by the user
