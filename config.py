import os
from datetime import timedelta
from dotenv import load_dotenv

# Load variables from .env file
load_dotenv()

class Config:
    """Application configuration settings."""
    
    # Core Flask Configuration
    SECRET_KEY = os.environ.get("SECRET_KEY", "secure-login-ai-dev-secret-key-2026")
    
    # Database Configuration (SQLite)
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'secure_login.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Session Security
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=60)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    
    # Application Firewall & Lockout Settings
    MAX_FAILED_ATTEMPTS = 3
    LOCKOUT_DURATION_MINUTES = 15
    RATE_LIMIT_WINDOW_SECONDS = 60
    MAX_REQUESTS_PER_WINDOW = 20
    
    # SMTP Email Configuration
    SMTP_SERVER = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
    SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
    SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "")
    SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")  # App-specific password
    SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "True").lower() in ("true", "1")
    ALERT_SENDER_EMAIL = os.environ.get("ALERT_SENDER_EMAIL", os.environ.get("SMTP_USERNAME", ""))
    
    # WhatsApp API Configuration
    # 1. CallMeBot Free WhatsApp API (Easiest & Free for students)
    CALLMEBOT_API_KEY = os.environ.get("CALLMEBOT_API_KEY", "")

    # 2. Twilio WhatsApp configuration
    TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID", "")
    TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN", "")
    TWILIO_WHATSAPP_NUMBER = os.environ.get("TWILIO_WHATSAPP_NUMBER", "whatsapp:+17372508034")
    TWILIO_CONTENT_SID = os.environ.get("TWILIO_CONTENT_SID", "")
    
    # 3. Generic REST WhatsApp Gateway (Alternative)
    WHATSAPP_API_URL = os.environ.get("WHATSAPP_API_URL", "")
    WHATSAPP_API_TOKEN = os.environ.get("WHATSAPP_API_TOKEN", "")
