from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import bcrypt
import secrets
import uuid

# SQLAlchemy instance
db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    
    # Fields for Email Verification
    is_active = db.Column(db.Boolean, nullable=False, default=False)
    verification_token = db.Column(db.String(100), unique=True, nullable=True)
    token_expiration_at = db.Column(db.DateTime, nullable=True)

    # Fields for Account Lockout
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

    # Fields for Password Reset
    reset_token = db.Column(db.String(128), unique=True, nullable=True)
    reset_token_expiration_at = db.Column(db.DateTime, nullable=True)

    # Fields for Two-Factor Authentication (2FA)
    has_2fa = db.Column(db.Boolean, default=False)
    totp_secret = db.Column(db.String(32), nullable=True)  # Increased to 32 for base32 encoded secrets
    trusted_device_uuid = db.Column(db.String(36), nullable=True)  # UUID for "remembered" devices

    # New field for recovery codes
    recovery_codes = db.Column(db.Text, nullable=True)  # Conceptual: store as JSON string or comma-separated

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login_at = db.Column(db.DateTime, nullable=True)
    # For future: password_expiry, last_password_change, etc.

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_password_allowed(self, password):
        # Prevent reuse of last 3 passwords
        history = PasswordHistory.query.filter_by(user_id=self.id).order_by(PasswordHistory.created_at.desc()).limit(3).all()
        for entry in history:
            if bcrypt.checkpw(password.encode('utf-8'), entry.password_hash.encode('utf-8')):
                return False
        return True

    def add_password_to_history(self, password):
        # Store new password hash in history
        ph = PasswordHistory(user_id=self.id, password_hash=bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'))
        db.session.add(ph)
        db.session.commit()
        # Keep only last 3
        history = PasswordHistory.query.filter_by(user_id=self.id).order_by(PasswordHistory.created_at.desc()).all()
        for entry in history[3:]:
            db.session.delete(entry)
        db.session.commit()

    def create_session(self, ip_address=None, user_agent=None):
        """Create a new session for this user"""
        session_token = secrets.token_urlsafe(32)
        user_session = UserSession(
            user_id=self.id,
            session_token=session_token,
            ip_address=ip_address,
            user_agent=user_agent,
            is_active=True
        )
        db.session.add(user_session)
        db.session.commit()
        return session_token

    def invalidate_other_sessions(self, current_session_token):
        """Invalidate all sessions except the current one"""
        UserSession.query.filter(
            UserSession.user_id == self.id,
            UserSession.session_token != current_session_token,
            UserSession.is_active == True
        ).update({'is_active': False})
        db.session.commit()

    def get_active_sessions(self):
        """Get all active sessions for this user"""
        return UserSession.query.filter_by(user_id=self.id, is_active=True).all()

    def generate_device_uuid(self):
        """Generate a new device UUID for trust"""
        return str(uuid.uuid4())

class PasswordHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class LoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    ip_address = db.Column(db.String(45))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    success = db.Column(db.Boolean, nullable=False)
    user_agent = db.Column(db.Text)

class UserSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    session_token = db.Column(db.String(64), unique=True, nullable=False)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationship
    user = db.relationship('User', backref='sessions')

    def update_activity(self):
        """Update the last activity timestamp"""
        self.last_activity = datetime.utcnow()
        db.session.commit()

    @staticmethod
    def get_session_by_token(session_token):
        """Get active session by token"""
        return UserSession.query.filter_by(
            session_token=session_token, 
            is_active=True
        ).first()

    @staticmethod
    def cleanup_expired_sessions():
        """Clean up sessions older than 24 hours"""
        from datetime import timedelta
        cutoff_time = datetime.utcnow() - timedelta(hours=24)
        UserSession.query.filter(
            UserSession.last_activity < cutoff_time,
            UserSession.is_active == True
        ).update({'is_active': False})
        db.session.commit() 