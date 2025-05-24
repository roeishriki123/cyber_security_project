import hashlib
import os
import re
from datetime import datetime, timedelta
from typing import Optional
from config import password_config

def generate_salt() -> str:
    return os.urandom(16).hex()

def hash_password(password: str, salt: str) -> str:
    """Hash password using HMAC-SHA256 with salt"""
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    )
    return key.hex()

def verify_password(plain_password: str, hashed_password: str, salt: str) -> bool:
    """Verify password against stored hash"""
    return hash_password(plain_password, salt) == hashed_password

def validate_password(password: str) -> tuple[bool, str]:
    """Validate password against configuration requirements"""
    if len(password) < password_config.MIN_LENGTH:
        return False, f"Password must be at least {password_config.MIN_LENGTH} characters long"
    
    if password_config.REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if password_config.REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if password_config.REQUIRE_NUMBERS and not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    
    if password_config.REQUIRE_SPECIAL_CHARS and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    
    # Check against forbidden words
    for word in password_config.FORBIDDEN_WORDS:
        if word.lower() in password.lower():
            return False, f"Password contains forbidden word: {word}"
    
    return True, "Password is valid"

def generate_reset_token() -> str:
    """Generate a SHA-1 hash for password reset"""
    random_bytes = os.urandom(32)
    return hashlib.sha1(random_bytes).hexdigest()

def is_login_blocked(last_attempt: Optional[datetime], attempts: int) -> bool:
    """Check if login should be blocked due to too many attempts"""
    if attempts >= password_config.MAX_LOGIN_ATTEMPTS:
        if last_attempt:
            # Block for 15 minutes after max attempts
            if datetime.utcnow() - last_attempt < timedelta(minutes=15):
                return True
    return False 