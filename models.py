from datetime import datetime, timezone, timedelta
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize SQLAlchemy
db = SQLAlchemy()

class User(db.Model):
    """User Model representing registered accounts."""
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    whatsapp_number = db.Column(db.String(20), nullable=False)
    failed_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationship to login logs
    login_logs = db.relationship("LoginLog", backref="user", lazy=True, cascade="all, delete-orphan")

    def set_password(self, password: str) -> None:
        """Securely hash and store password using Werkzeug pbkdf2/scrypt."""
        self.password_hash = generate_password_hash(password, method="scrypt")

    def check_password(self, password: str) -> bool:
        """Verify candidate password against securely hashed password."""
        return check_password_hash(self.password_hash, password)

    def is_locked(self) -> bool:
        """Check if account is currently locked."""
        if not self.locked_until:
            return False
        # Normalize timezone comparison
        now = datetime.now(timezone.utc)
        lock_time = self.locked_until
        if lock_time.tzinfo is None:
            lock_time = lock_time.replace(tzinfo=timezone.utc)
        return now < lock_time

    def get_remaining_lockout_minutes(self) -> int:
        """Calculate how many minutes remain in the lockout period."""
        if not self.is_locked():
            return 0
        now = datetime.now(timezone.utc)
        lock_time = self.locked_until
        if lock_time.tzinfo is None:
            lock_time = lock_time.replace(tzinfo=timezone.utc)
        delta = lock_time - now
        return max(1, int(delta.total_seconds() // 60) + 1)

    def lock_account(self, minutes: int = 15) -> None:
        """Lock account for a specified duration."""
        self.locked_until = datetime.now(timezone.utc) + timedelta(minutes=minutes)

    def reset_failed_attempts(self) -> None:
        """Reset failed attempt counter and clear any lockout status."""
        self.failed_attempts = 0
        self.locked_until = None

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email}>"


class LoginLog(db.Model):
    """Audit and Analytics log for every authentication attempt."""
    __tablename__ = "login_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    email_attempted = db.Column(db.String(120), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    success = db.Column(db.Boolean, nullable=False, default=False)
    failed_attempt_count = db.Column(db.Integer, nullable=False, default=0)
    ip_address = db.Column(db.String(45), nullable=False, default="127.0.0.1")
    user_agent = db.Column(db.String(255), nullable=True)
    risk_score = db.Column(db.Float, nullable=False, default=0.0)
    status = db.Column(db.String(30), nullable=False, default="FAILED")  # SUCCESS, FAILED, SUSPICIOUS, BLOCKED

    def to_dict(self):
        """Convert log entry to dictionary (excluding sensitive info)."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "email_attempted": self.email_attempted,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S") if self.timestamp else "",
            "success": self.success,
            "failed_attempt_count": self.failed_attempt_count,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "risk_score": round(self.risk_score, 2),
            "status": self.status,
        }

    def __repr__(self) -> str:
        return f"<LoginLog id={self.id} email={self.email_attempted} status={self.status} risk={self.risk_score}>"
