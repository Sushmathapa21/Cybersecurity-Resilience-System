import os
import secrets
import requests
import smtplib
import ssl
import base64
import io
from email.mime.text import MIMEText
from flask import Flask, render_template, redirect, url_for, flash, session, request, send_from_directory, make_response, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from forms import RegistrationForm, LoginForm, RequestResetForm, ResetPasswordForm, ChangePasswordForm, TwoFAVerificationForm
from models import db, User, PasswordHistory, LoginLog, UserSession
from werkzeug.security import check_password_hash
from datetime import datetime, timedelta, timezone
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_migrate import Migrate
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import traceback
from functools import wraps
from flask_wtf.csrf import CSRFError, generate_csrf
import pyotp
import qrcode
import uuid
import json

# Flask app setup
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_urlsafe(32)  # Secure random secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Thapa%40302119@localhost:3306/acs'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Mitigate XSS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Mitigate CSRF
app.config['RECAPTCHA_SITE_KEY'] = '6Lerem0rAAAAAKeS1lpeFrimSaoiuAwov6Vjxk7P'
app.config['RECAPTCHA_SECRET_KEY'] = '6Lerem0rAAAAAB9pCPyP2T0DSKsoTl40ovzNkO84'
#app.config['SENDGRID_API_KEY'] = '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'  # Replace with your real key
app.config['SENDGRID_API_KEY'] = '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'  # Replace with your real key

# Flask-Mail Configuration for smtplib
app.config['MAIL_SERVER'] = 'smtp.gmail.net'
app.config['MAIL_PORT'] = 587 # Port for STARTTLS
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'thapasushma3021@gmail.com'
app.config['MAIL_PASSWORD'] = 'fsxt kgol zhkt zgjr'
app.config['MAIL_DEFAULT_SENDER'] = ("thapasushma3021@gmail.com", "thapasushma3021@gmail.com")
#app.config['MAIL_DEFAULT_SENDER'] = ("sushmathapa.3021@gmail.com", "sushmathapa.3021@gmail.com")

# Initialize extensions
db.init_app(app)
csrf = CSRFProtect(app)

# Flask-Limiter Configuration
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",  # Changed back from redis:// to memory:// for local development
)

# After db.init_app(app)
migrate = Migrate(app, db)

# Session cleanup function
def cleanup_expired_sessions():
    """Clean up expired sessions - can be called periodically"""
    try:
        UserSession.cleanup_expired_sessions()
        print("Session cleanup completed successfully")
    except Exception as e:
        print(f"Error during session cleanup: {e}")

# Send email via Gmail SMTP (replaces SendGrid)
def send_email_via_gmail(recipient_email, subject, body_html):
    """Sends an email using Gmail SMTP. Returns True on success, False on failure."""
    sender_email = app.config.get('MAIL_USERNAME')
    app_password = app.config.get('MAIL_PASSWORD')
    msg = MIMEText(body_html, "html")
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = recipient_email
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, app_password)
            server.sendmail(sender_email, recipient_email, msg.as_string())
            print("Email sent successfully via Gmail SMTP!")
            return True
    except Exception as e:
        print(f"Gmail SMTP Exception: {e}")
        return False

@app.route('/test_image')
@csrf.exempt 
def test_image():
    return f'<img src="{url_for("static", filename="images/logo.png")}"><p>If you see the logo, static files are working!</p>'

@app.route('/debug/user/<username>')
def debug_user(username):
    """Debug route to check user 2FA status"""
    user = User.query.filter_by(username=username).first()
    if not user:
        return f"User '{username}' not found"
    
    return f"""
    <h2>User Debug Info: {user.username}</h2>
    <ul>
        <li>Email: {user.email}</li>
        <li>Active: {user.is_active}</li>
        <li>Has 2FA: {user.has_2fa}</li>
        <li>TOTP Secret: {'SET' if user.totp_secret else 'NOT SET'}</li>
        <li>Trusted Device UUID: {user.trusted_device_uuid or 'NOT SET'}</li>
        <li>Failed Login Attempts: {user.failed_login_attempts}</li>
        <li>Locked Until: {user.locked_until or 'NOT LOCKED'}</li>
    </ul>
    """

@app.route('/', methods=['GET', 'POST'])
@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5/minute")
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Google reCAPTCHA v2 validation
        recaptcha_response = request.form.get('g-recaptcha-response')
        if not recaptcha_response:
            flash('Please complete the reCAPTCHA.', 'danger')
            return render_template('register.html', form=form)
        recaptcha_secret = app.config['RECAPTCHA_SECRET_KEY']
        verify_url = 'https://www.google.com/recaptcha/api/siteverify'
        payload = {'secret': recaptcha_secret, 'response': recaptcha_response, 'remoteip': request.remote_addr}
        r = requests.post(verify_url, data=payload)
        result = r.json()
        if not result.get('success'):
            flash('Incorrect CAPTCHA. Please try again.', 'danger')
            return render_template('register.html', form=form)
        # Username uniqueness
        # if User.query.filter_by(username=form.username.data).first():
        #     flash('Username already exists. Please choose another.', 'danger')
        #     return render_template('register.html', form=form)
        # # Password history check
        # user = User.query.filter_by(username=form.username.data).first()
        # if user and not user.is_password_allowed(form.password.data):
        #     flash('You cannot reuse your last 3 passwords.', 'danger')
        #     return render_template('register.html', form=form)
        # Register user
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        user.add_password_to_history(form.password.data)
        db.session.commit()

        # Generate verification token
        token = secrets.token_urlsafe(32)
        token_expiration = datetime.utcnow() + timedelta(hours=24)
        user.verification_token = token
        user.token_expiration_at = token_expiration
        db.session.commit()

        # Send activation email using Gmail SMTP
        activation_link = url_for('verify_account', token=token, _external=True)
        subject = "Your SecureApp Registration"
        html_body = f"<p>Thank you for registering with SecureApp.</p><p>To complete your registration, please visit the following link:</p><p><a href='{activation_link}'>Complete Registration</a></p><p>This link will expire in 24 hours.</p>"
        print(f"DEBUG: Attempting to send activation email to {user.email} with subject '{subject}' and link: {activation_link}")
        try:
            email_sent = send_email_via_gmail(user.email, subject, html_body)
            print(f"DEBUG: send_email_via_gmail returned: {email_sent}")
        except Exception as e:
            print(f"ERROR: Exception during send_email_via_gmail: {e}")
            email_sent = False
        if email_sent:
            flash('Registration successful! Please check your email to activate your account.', 'success')
            return redirect(url_for('registration_success'))
        else:
            flash('Could not send activation email. Please try again later.', 'danger')
            return render_template('register.html', form=form)
    # On GET or failed POST, show the form
    return render_template('register.html', form=form)

@app.route('/registration-success')
def registration_success():
    return render_template('registration_success.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        flash('You are already logged in.', 'info')
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        username_or_email = form.username.data.strip()
        print(f"DEBUG: Login attempt for input: {username_or_email}")
        
        # Robust user lookup: try username first, then email
        user = User.query.filter_by(username=username_or_email).first()
        lookup_method = "username"
        
        if not user:
            # Try email if username lookup failed
            user = User.query.filter_by(email=username_or_email).first()
            lookup_method = "email"
        
        if user:
            print(f"DEBUG: Login attempt for user: {user.username} ({user.email})")
            print(f"DEBUG: User active: {user.is_active}, Locked until: {user.locked_until}, Failed attempts: {user.failed_login_attempts}")
            print(f"DEBUG: User has_2fa status: {user.has_2fa}")  # <--- CRITICAL DEBUG PRINT
            
            # Check if account is locked
            if user.locked_until and user.locked_until > datetime.utcnow():
                remaining_time = user.locked_until - datetime.utcnow()
                minutes = int(remaining_time.total_seconds() / 60)
                flash(f'Account is locked. Please try again in {minutes} minutes.', 'danger')
                print(f"DEBUG: Account {user.username} is locked.")
                return render_template('login.html', form=form)
            
            # Check if account is active
            if not user.is_active:
                flash('Please verify your email address before logging in.', 'warning')
                print(f"DEBUG: Account {user.username} not active.")
                return render_template('login.html', form=form)
            
            # --- REAL PASSWORD CHECK HERE ---
            if user.check_password(form.password.data):
                print(f"DEBUG: Password verification successful for user: {user.username}")
                print(f"DEBUG: User {user.username} has_2fa status BEFORE redirect: {user.has_2fa}")  # <--- THIS LINE IS ALSO IMPORTANT
                
                # Password is correct. Now, check 2FA status.
                if user.has_2fa:  # <--- THIS IS THE CRITICAL CHECK
                    # If 2FA is enabled, redirect to 2FA verification page
                    session['2fa_pending_user_id'] = user.id
                    session['2fa_pending_username'] = user.username
                    print(f"DEBUG: 2FA enabled for {user.username}. Redirecting to 2FA verification.")
                    return redirect(url_for('verify_2fa'))  # <--- REDIRECT TO 2FA VERIFY ROUTE
                else:
                    # No 2FA, proceed with normal login
                    # Create session token for the user
                    session_token = user.create_session(
                        ip_address=request.remote_addr,
                        user_agent=request.headers.get('User-Agent')
                    )
                    
                    session['user_id'] = user.id
                    session['username'] = user.username
                    session['session_token'] = session_token
                    
                    user.failed_login_attempts = 0
                    user.last_login_at = datetime.utcnow()
                    db.session.commit()
                    login_log = LoginLog(
                        user_id=user.id,
                        ip_address=request.remote_addr,
                        success=True,
                        user_agent=request.headers.get('User-Agent')
                    )
                    db.session.add(login_log)
                    db.session.commit()
                    flash('Login successful!', 'success')
                    return redirect(url_for('dashboard'))
            else:
                # Password did not match
                print(f"DEBUG: Password mismatch for {user.username}.")
                flash('Invalid username or password.', 'danger')
                user.failed_login_attempts += 1
                
                # Lock account after 5 failed attempts for 15 minutes
                if user.failed_login_attempts >= 5:
                    user.locked_until = datetime.utcnow() + timedelta(minutes=15)
                    flash('Too many failed login attempts. Account locked for 15 minutes.', 'danger')
                    print(f"DEBUG: Account {user.username} locked due to failed attempts.")
                
                login_log = LoginLog(
                    user_id=user.id,
                    ip_address=request.remote_addr,
                    success=False,
                    user_agent=request.headers.get('User-Agent')
                )
                db.session.add(login_log)
                db.session.commit()
                return render_template('login.html', form=form)
        else:
            # User not found by username or email
            print(f"DEBUG: Login attempt for '{username_or_email}' - User not found.")
            flash('Invalid username or password.', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/verify/<token>')
def verify_account(token):
    try:
        user = User.query.filter_by(verification_token=token).first()
        if not user:
            flash('Invalid activation token.', 'danger')
            return redirect(url_for('login'))

        if user.token_expiration_at < datetime.utcnow():
            # In a real app, you might want to allow resending the token
            flash('Activation token has expired.', 'danger')
            return redirect(url_for('register')) # Prompt to re-register

        user.is_active = True
        user.verification_token = None
        user.token_expiration_at = None
        user.failed_login_attempts = 0 # Reset on activation
        db.session.commit()
        
        flash('Your account has been successfully activated! You can now log in.', 'success')
        return redirect(url_for('login'))

    except Exception as e:
        print(f"Verification Error: {e}")
        traceback.print_exc()
        flash('An error occurred during account verification.', 'danger')
        return redirect(url_for('error_page'))

@app.route('/request_reset', methods=['GET', 'POST'])
def request_reset():
    form = RequestResetForm()
    if form.validate_on_submit():
        print("DEBUG: request_reset() - Form validated on submit.")
        user = User.query.filter_by(email=form.email.data).first()

        if user:
            print(f"DEBUG: request_reset() - User found: {user.email}")
            token = secrets.token_urlsafe(32)
            user.reset_token = token
            user.reset_token_expiration_at = datetime.utcnow() + timedelta(hours=1)
            db.session.commit()
            print("DEBUG: request_reset() - Token generated and committed.")

            reset_url = url_for('reset_token', token=token, _external=True)
            subject = 'SecureApp Password Reset Request'
            html_body = f"To reset your password, visit the following link:<br><a href='{reset_url}'>{reset_url}</a><br>If you did not request this, please ignore this email."

            SIMULATE_RESET_EMAIL_FOR_DEMO = False  # Now use real Gmail SMTP
            print(f"DEBUG: request_reset() - SIMULATE_RESET_EMAIL_FOR_DEMO is set to: {SIMULATE_RESET_EMAIL_FOR_DEMO}")

            if SIMULATE_RESET_EMAIL_FOR_DEMO:
                print(f"SIMULATED EMAIL (Password Reset): To: {user.email}, Subject: {subject}, Link: {reset_url}")
                email_sent_successfully = True
            else:
                print("DEBUG: request_reset() - Sending real email via Gmail SMTP...")
                email_sent_successfully = send_email_via_gmail(user.email, subject, html_body)
                print(f"DEBUG: request_reset() - Email sent: {email_sent_successfully}")

            if not email_sent_successfully:
                flash('An issue occurred while attempting to send the reset link. Please try again later.', 'danger')
                return redirect(url_for('request_reset'))
        else:
            print(f"DEBUG: request_reset() - User with email '{form.email.data}' NOT found.")

        flash('If an account with that email exists, a password reset link has been sent.', 'info')
        return redirect(url_for('login'))

    else:
        print("DEBUG: request_reset() - Form validation FAILED.")
        print(f"DEBUG: request_reset() - Form errors: {form.errors}")

    return render_template('request_reset.html', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    user = User.query.filter_by(reset_token=token).first()
    if not user or not user.reset_token_expiration_at or user.reset_token_expiration_at < datetime.utcnow():
        flash('Invalid or expired token.', 'danger')
        return redirect(url_for('request_reset'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        user.reset_token = None
        user.reset_token_expiration_at = None
        db.session.commit()
        flash('Your password has been reset! You may now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)

# --- Login Required Decorator ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or 'session_token' not in session:
            session.clear()
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        
        # Check if session is valid
        user_session = UserSession.get_session_by_token(session['session_token'])
        if not user_session or user_session.user_id != session['user_id']:
            session.clear()
            flash('Your session has expired. Please log in again.', 'warning')
            return redirect(url_for('login'))
        
        # Update session activity
        user_session.update_activity()
        
        return f(*args, **kwargs)
    return decorated_function

@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        flash('User session invalid. Please log in again.', 'warning')
        return redirect(url_for('login'))
    
    # Security status
    account_status = 'Active' if user.is_active else 'Inactive'
    last_login = user.last_login_at
    
    # Last 5 successful logins for better overview
    recent_logins = LoginLog.query.filter_by(user_id=user.id, success=True).order_by(LoginLog.timestamp.desc()).limit(5).all()
    
    return render_template('dashboard.html',
        account_status=account_status,
        last_login=last_login,
        recent_logins=recent_logins,
        user=user
    )

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        flash('User session invalid. Please log in again.', 'warning')
        return redirect(url_for('login'))
    
    change_password_form = ChangePasswordForm()
    login_logs = LoginLog.query.filter_by(user_id=user.id).order_by(LoginLog.timestamp.desc()).limit(50).all()
    
    # Get active sessions for this user
    active_sessions = user.get_active_sessions()
    
    # Handle password change
    if request.method == 'POST' and 'old_password' in request.form:
        # Store old password in session to preserve it
        old_password = request.form.get('old_password', '')
        session['temp_old_password'] = old_password
        
        print(f"DEBUG: Old password from form: '{old_password}'")
        print(f"DEBUG: Session temp_old_password: '{session.get('temp_old_password', '')}'")
        
        # Create form with data
        change_password_form = ChangePasswordForm(data={
            'old_password': old_password,
            'new_password': request.form.get('new_password', ''),
            'confirm_new_password': request.form.get('confirm_new_password', '')
        })
        
        print(f"DEBUG: Form old_password.data after creation: '{change_password_form.old_password.data}'")
        
        if change_password_form.validate_on_submit():
            # Form validation passed, now check business logic
            if not user.check_password(change_password_form.old_password.data):
                flash('Your current password is incorrect. Please try again.', 'danger')
                # Preserve old password, clear new passwords
                change_password_form.old_password.data = old_password
                change_password_form.new_password.data = ''
                change_password_form.confirm_new_password.data = ''
                print(f"DEBUG: After incorrect password - old_password.data: '{change_password_form.old_password.data}'")
            elif not user.is_password_allowed(change_password_form.new_password.data):
                flash('You cannot reuse your last 3 passwords. Please choose a different password.', 'danger')
                # Preserve old password, clear new passwords
                change_password_form.old_password.data = old_password
                change_password_form.new_password.data = ''
                change_password_form.confirm_new_password.data = ''
                print(f"DEBUG: After password reuse - old_password.data: '{change_password_form.old_password.data}'")
            else:
                # All validations passed, update password
                user.set_password(change_password_form.new_password.data)
                user.add_password_to_history(change_password_form.new_password.data)
                db.session.commit()
                # Clear temporary session data
                session.pop('temp_old_password', None)
                flash('Your password has been successfully updated!', 'success')
                return redirect(url_for('profile') + '#password')
        else:
            # Form validation failed - preserve old password, clear new passwords
            change_password_form.old_password.data = old_password
            change_password_form.new_password.data = ''
            change_password_form.confirm_new_password.data = ''
            print(f"DEBUG: After validation failure - old_password.data: '{change_password_form.old_password.data}'")
            print(f"DEBUG: Form errors: {change_password_form.errors}")
            # No flash message needed as field-specific errors will be displayed
            pass
    else:
        # GET request or no old_password in form - restore old password from session if available
        if 'temp_old_password' in session:
            change_password_form.old_password.data = session['temp_old_password']
            print(f"DEBUG: Restored from session - old_password.data: '{change_password_form.old_password.data}'")
    
    print(f"DEBUG: Final old_password.data before render: '{change_password_form.old_password.data}'")
    
    # Pass the preserved old password directly to template
    preserved_old_password = change_password_form.old_password.data or session.get('temp_old_password', '')
    
    # Get current session token for template
    current_session_token = session.get('session_token')
    
    return render_template('profile.html', 
                         login_logs=login_logs, 
                         change_password_form=change_password_form, 
                         current_user=user,
                         preserved_old_password=preserved_old_password,
                         active_sessions=active_sessions,
                         current_session_token=current_session_token)

@app.route('/logout')
@login_required
def logout():
    # Invalidate current session
    if 'session_token' in session:
        user_session = UserSession.get_session_by_token(session['session_token'])
        if user_session:
            user_session.is_active = False
            db.session.commit()
    
    session.clear()
    flash('You have been logged out securely.', 'info')
    return redirect(url_for('login'))

@app.route('/logout_others', methods=['POST'])
@login_required
@csrf.exempt # For AJAX calls
def logout_others():
    try:
        user = User.query.get(session['user_id'])
        if not user:
            return jsonify(success=False, message="User not found."), 404
        
        # Get current session token
        current_session_token = session.get('session_token')
        if not current_session_token:
            return jsonify(success=False, message="No active session found."), 400
        
        # Get count of other active sessions before invalidating
        other_sessions_count = UserSession.query.filter(
            UserSession.user_id == user.id,
            UserSession.session_token != current_session_token,
            UserSession.is_active == True
        ).count()
        
        # Invalidate all other sessions for this user
        user.invalidate_other_sessions(current_session_token)
        
        # Create success message
        if other_sessions_count > 0:
            message = f"Successfully terminated {other_sessions_count} other active session(s)."
        else:
            message = "No other active sessions were found to terminate."
        
        flash(message, 'success')
        return jsonify(success=True, message=message), 200
        
    except Exception as e:
        print(f"Error in /logout_others: {e}")
        import traceback
        traceback.print_exc()
        return jsonify(success=False, message="An error occurred while ending other sessions."), 500

@app.route('/delete_account', methods=['POST'])
@csrf.exempt
@login_required
def delete_account():
    print(f"DEBUG: Delete account request received for user_id: {session.get('user_id')}")
    
    user = User.query.get(session['user_id'])
    if not user:
        # User not found in DB but in session (session invalid or DB desync)
        print(f"DEBUG: User not found in database for user_id: {session.get('user_id')}")
        session.clear()
        return jsonify({
            'success': False, 
            'message': 'User session invalid. Please log in again.'
        }), 401 # Unauthorized
    
    try:
        print(f"DEBUG: Found user: {user.username} (ID: {user.id})")
        print(f"DEBUG: About to delete user and all associated data...")
        
        # Get count of related records before deletion for verification
        password_history_count = PasswordHistory.query.filter_by(user_id=user.id).count()
        login_log_count = LoginLog.query.filter_by(user_id=user.id).count()
        session_count = UserSession.query.filter_by(user_id=user.id).count()
        
        print(f"DEBUG: Related records - PasswordHistory: {password_history_count}, LoginLog: {login_log_count}, UserSession: {session_count}")
        
        # Manually delete related records first (more reliable than relying on cascade)
        PasswordHistory.query.filter_by(user_id=user.id).delete()
        LoginLog.query.filter_by(user_id=user.id).delete()
        UserSession.query.filter_by(user_id=user.id).delete()
        
        # Now delete the user
        db.session.delete(user)
        db.session.commit()
        
        print(f"DEBUG: User deletion successful. Session cleared.")
        
        session.clear() # Clear session after deletion
        flash('Your account has been permanently deleted.', 'info') # Flash message for the redirect
        
        return jsonify({
            'success': True, 
            'redirect_url': url_for('register'),
            'message': 'Account deleted successfully.'
        })
    except Exception as e:
        db.session.rollback() # Rollback any partial deletions
        print(f"ERROR: Error during account deletion for user_id {session.get('user_id')}: {e}")
        import traceback # Ensure this is at the top
        traceback.print_exc()
        return jsonify({
            'success': False, 
            'message': 'An error occurred while deleting your account.'
        }), 500

@app.route('/profile/2fa/enable', methods=['GET', 'POST'])
@login_required
def enable_2fa():
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        flash('User session invalid. Please log in again.', 'warning')
        return redirect(url_for('login'))
    
    # If 2FA is already enabled, redirect back to profile
    if user.has_2fa:
        flash('2FA is already enabled for your account.', 'info')
        return redirect(url_for('profile') + '#2fa')
    
    form = TwoFAVerificationForm()
    
    # Generate real TOTP secret and QR code (for both GET and POST)
    totp_secret = session.get('2fa_temp_secret')
    if not totp_secret:
        totp_secret = pyotp.random_base32()
        session['2fa_temp_secret'] = totp_secret
    
    # Generate provisioning URI for QR code
    totp = pyotp.TOTP(totp_secret)
    provisioning_uri = totp.provisioning_uri(
        name=user.email,
        issuer_name="SecureApp"
    )
    
    # Generate QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    
    # Create QR code image
    qr_image = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64
    buffer = io.BytesIO()
    qr_image.save(buffer, format='PNG')
    qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    # Generate mock recovery codes
    recovery_codes = [f"REC-{uuid.uuid4().hex[:8].upper()}" for _ in range(6)]
    user.recovery_codes = json.dumps(recovery_codes)
    
    if request.method == 'GET':
        return render_template('2fa_setup.html', form=form, totp_secret=totp_secret, qr_code_base64=qr_code_base64, recovery_codes=recovery_codes)
    
    if form.validate_on_submit():
        # Get the real generated secret from session
        totp_secret = session.get('2fa_temp_secret')
        if not totp_secret:
            flash('2FA setup session expired. Please try again.', 'danger')
            return redirect(url_for('enable_2fa'))
        
        # Create TOTP object and verify the code
        totp = pyotp.TOTP(totp_secret)
        if totp.verify(form.code.data, valid_window=1):  # Allow current and previous 30-sec window
            # Enable 2FA
            user.has_2fa = True
            user.totp_secret = totp_secret
            db.session.commit()
            
            # Clear temporary secret from session
            session.pop('2fa_temp_secret', None)
            
            flash('2FA enabled successfully! Your account is now protected with two-factor authentication. Save your recovery codes. Use them if you lose your authenticator.', 'success')
            return redirect(url_for('twofa_success'))
        else:
            flash('Invalid verification code. Please try again.', 'danger')
    
    # Re-render form with errors or on failed validation
    return render_template('2fa_setup.html', form=form, totp_secret=totp_secret, qr_code_base64=qr_code_base64, recovery_codes=recovery_codes)

@app.route('/2fa_verify', methods=['GET', 'POST'])
def verify_2fa():
    """2FA verification during login"""
    # Check if user is pending 2FA verification
    if '2fa_pending_user_id' not in session:
        flash('No 2FA verification pending. Please log in.', 'warning')
        return redirect(url_for('login'))
    
    user = User.query.get(session['2fa_pending_user_id'])
    if not user or not user.has_2fa:
        session.pop('2fa_pending_user_id', None)
        session.pop('2fa_pending_username', None)
        flash('Invalid 2FA verification request.', 'danger')
        return redirect(url_for('login'))
    
    form = TwoFAVerificationForm()
    
    if form.validate_on_submit():
        # Verify the TOTP code
        if user.totp_secret:
            totp = pyotp.TOTP(user.totp_secret)
            if totp.verify(form.code.data, valid_window=1):  # Allow current and previous 30-sec window
                # Handle "Remember This Device" option
                if form.remember_device.data:
                    device_uuid = user.generate_device_uuid()
                    user.trusted_device_uuid = device_uuid
                    db.session.commit()
                    
                    # Create session token for the user
                    session_token = user.create_session(
                        ip_address=request.remote_addr,
                        user_agent=request.headers.get('User-Agent')
                    )
                    
                    # Set device cookie (30 days)
                    response = make_response(redirect(url_for('dashboard')))
                    response.set_cookie('device_uuid', device_uuid, max_age=30*24*60*60, httponly=True, samesite='Lax')
                    
                    # Complete login
                    session['user_id'] = user.id
                    session['username'] = user.username
                    session['session_token'] = session_token
                    user.failed_login_attempts = 0
                    user.last_login_at = datetime.utcnow()
                    db.session.commit()
                    login_log = LoginLog(
                        user_id=user.id,
                        ip_address=request.remote_addr,
                        success=True,
                        user_agent=request.headers.get('User-Agent')
                    )
                    db.session.add(login_log)
                    db.session.commit()
                    flash('Device remembered for 30 days. You won\'t need 2FA on this device.', 'success')
                    return response
                else:
                    # Create session token for the user
                    session_token = user.create_session(
                        ip_address=request.remote_addr,
                        user_agent=request.headers.get('User-Agent')
                    )
                    
                    # Complete login without device trust
                    session['user_id'] = user.id
                    session['username'] = user.username
                    session['session_token'] = session_token
                    user.failed_login_attempts = 0
                    user.last_login_at = datetime.utcnow()
                    db.session.commit()
                    login_log = LoginLog(
                        user_id=user.id,
                        ip_address=request.remote_addr,
                        success=True,
                        user_agent=request.headers.get('User-Agent')
                    )
                    db.session.add(login_log)
                    db.session.commit()
                    flash('2FA verification successful!', 'success')
                    return redirect(url_for('dashboard'))
            else:
                # Increment failed login attempts for 2FA failures
                user.failed_login_attempts += 1
                db.session.commit()
                flash('Invalid 2FA code. Please try again.', 'danger')
        else:
            flash('2FA configuration error. Please contact support.', 'danger')
    
    return render_template('2fa_verify.html', form=form)

@app.route('/profile/2fa/disable', methods=['POST'])
@csrf.exempt
@login_required
def disable_2fa():
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        flash('User session invalid. Please log in again.', 'warning')
        return redirect(url_for('login'))
    
    if user.has_2fa:
        user.has_2fa = False
        user.totp_secret = None
        user.trusted_device_uuid = None  # Clear trusted device
        db.session.commit()
        flash('2FA has been disabled for your account.', 'info')
    else:
        flash('2FA is not enabled for your account.', 'warning')
    
    return jsonify({
        'success': True,
        'message': '2FA disabled successfully.'
    })

@app.route('/profile/2fa/forget_device', methods=['POST'])
@csrf.exempt
@login_required
def forget_device():
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        return jsonify({
            'success': False,
            'message': 'User session invalid. Please log in again.'
        }), 401
    
    if user.has_2fa and user.trusted_device_uuid:
        user.trusted_device_uuid = None
        db.session.commit()
        
        # Create response to clear the device cookie
        response = jsonify({
            'success': True,
            'message': 'Device forgotten successfully. You will need to enter 2FA codes on your next login.'
        })
        response.delete_cookie('device_uuid')
        return response
    else:
        return jsonify({
            'success': False,
            'message': 'No trusted device found to forget.'
        }), 400

@app.errorhandler(400)
def bad_request(e):
    return render_template('error.html', message="Bad request."), 400

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', message="Page not found."), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', message="An internal error occurred."), 500

@app.errorhandler(429)
def rate_limit_handler(e):
    print(f"DEBUG: Rate limit handler activated. Error: {e.description}")
    return render_template('error.html', error_code=429, error_message="Too Many Requests", error_details=f"You have exceeded the rate limit. Please try again later. The limit is {e.description}.")

@app.route('/error_page')
def error_page():
    return render_template('error.html', message="An unexpected error occurred during processing.")

@app.route('/cleanup-sessions')
@login_required
def cleanup_sessions():
    """Manual session cleanup endpoint for testing"""
    try:
        cleanup_expired_sessions()
        flash('Session cleanup completed successfully.', 'success')
    except Exception as e:
        flash(f'Error during session cleanup: {e}', 'danger')
    return redirect(url_for('profile'))

@app.route('/test_db')
def test_db():
    """Test database connectivity and user existence"""
    try:
        # Test database connection
        users = User.query.all()
        user_count = len(users)
        
        # Get first few users for debugging
        sample_users = User.query.limit(5).all()
        user_info = []
        for user in sample_users:
            user_info.append({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_active': user.is_active,
                'has_2fa': user.has_2fa
            })
        
        return jsonify({
            'status': 'success',
            'message': 'Database connection successful',
            'user_count': user_count,
            'sample_users': user_info
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Database error: {str(e)}'
        }), 500

@app.route('/test_user/<username>')
def test_user(username):
    """Test if a specific user exists and their password verification"""
    try:
        # Try to find user by username
        user = User.query.filter_by(username=username).first()
        if not user:
            # Try by email
            user = User.query.filter_by(email=username).first()
        
        if user:
            return jsonify({
                'status': 'success',
                'user_found': True,
                'user_info': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'is_active': user.is_active,
                    'has_2fa': user.has_2fa,
                    'failed_login_attempts': user.failed_login_attempts,
                    'locked_until': str(user.locked_until) if user.locked_until else None
                }
            })
        else:
            return jsonify({
                'status': 'success',
                'user_found': False,
                'message': f'User "{username}" not found'
            })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error: {str(e)}'
        }), 500

@app.route('/profile/2fa/welcome')
@login_required
def welcome_2fa():
    """Welcome page for 2FA setup with introduction and instructions"""
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        flash('User session invalid. Please log in again.', 'warning')
        return redirect(url_for('login'))
    
    # If 2FA is already enabled, redirect to profile
    if user.has_2fa:
        flash('2FA is already enabled for your account.', 'info')
        return redirect(url_for('profile') + '#2fa')
    
    return render_template('2fa_welcome.html')

@app.route('/profile/2fa/success')
@login_required
def twofa_success():
    """Success page shown after 2FA is enabled"""
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        flash('User session invalid. Please log in again.', 'warning')
        return redirect(url_for('login'))
    
    # Only show success page if 2FA is actually enabled
    if not user.has_2fa:
        flash('2FA is not enabled for your account.', 'warning')
        return redirect(url_for('profile') + '#2fa')
    
    return render_template('2fa_success.html')

if __name__ == '__main__':
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Thapa%40302119@localhost:3306/acs'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    with app.app_context():
        # db.create_all()
        pass
    app.run(debug=True, port=5001)