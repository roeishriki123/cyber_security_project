from pydantic import BaseSettings

class PasswordConfig(BaseSettings):
    MIN_LENGTH: int = 10
    REQUIRE_UPPERCASE: bool = True
    REQUIRE_LOWERCASE: bool = True
    REQUIRE_NUMBERS: bool = True
    REQUIRE_SPECIAL_CHARS: bool = True
    PASSWORD_HISTORY: int = 3
    MAX_LOGIN_ATTEMPTS: int = 3
    FORBIDDEN_WORDS: list = ["password", "admin", "123456", "qwerty"]
    
    class Config:
        env_file = ".env"

password_config = PasswordConfig()

# Password Configuration
PASSWORD_MIN_LENGTH = 10
PASSWORD_REQUIRE_UPPER = True
PASSWORD_REQUIRE_LOWER = True
PASSWORD_REQUIRE_DIGITS = True
PASSWORD_REQUIRE_SPECIAL = True
PASSWORD_HISTORY_SIZE = 3  # Number of previous passwords to remember
MAX_LOGIN_ATTEMPTS = 3  # Maximum number of failed login attempts

# Common password dictionary to prevent
COMMON_PASSWORDS = [
    "password123", "12345678", "qwerty123", "admin123",
    "welcome123", "letmein123", "monkey123", "dragon123",
    "baseball123", "football123", "shadow123", "michael123",
    "jennifer123", "thomas123", "jessica123", "joshua123",
    "michelle123", "charlie123", "andrew123", "matthew123",
    "password1", "123456789", "qwerty", "admin",
    "welcome", "letmein", "monkey", "dragon",
    "baseball", "football", "shadow", "michael",
    "jennifer", "thomas", "jessica", "joshua",
    "michelle", "charlie", "andrew", "matthew"
]

# Special characters allowed in passwords
SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?" 