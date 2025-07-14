from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Regexp, ValidationError, Email, EqualTo
import re

# Password strength criteria
class PasswordStrength:
    @staticmethod
    def score(password):
        score = 0
        length = len(password)
        if length >= 16:
            score += 2
        elif length >= 12:
            score += 1
        if re.search(r'[A-Z]', password):
            score += 1
        if re.search(r'[a-z]', password):
            score += 1
        if re.search(r'\d', password):
            score += 1
        if re.search(r'[^A-Za-z0-9]', password):
            score += 1
        # Penalize common patterns
        if re.search(r'(.)\1{2,}', password):
            score -= 1
        if re.search(r'(1234|abcd|password|qwerty|letmein)', password, re.IGNORECASE):
            score -= 2
        if re.search(r'(\w{3,})\1', password):
            score -= 1
        return score

    @staticmethod
    def label(score):
        if score <= 1:
            return 'Very Weak'
        elif score == 2:
            return 'Weak'
        elif score == 3:
            return 'Good'
        elif score == 4:
            return 'Strong'
        else:
            return 'Very Strong'

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=4, max=20),
        Regexp(r'^[A-Za-z0-9_]+$', message='Username must contain only letters, numbers, and underscores.')
    ])
    email = StringField('Email', validators=[
        DataRequired(),
        Email(message='Invalid email address.')
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long."),
        Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$',
               message="Password must include at least one uppercase letter, one lowercase letter, one number, and one special character.")
    ])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match.')])
    submit = SubmitField('Register')

    def validate_password(self, field):
        score = PasswordStrength.score(field.data)
        if score < 3:
            raise ValidationError('Password is too weak. Please choose a stronger password.')
        # For demonstration, more checks can be added here (e.g., dictionary words, entropy)

    def validate_email(self, field):
        from models import User
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered. Please use a different email address.')

class LoginForm(FlaskForm):
    """Simple login form for demonstration (no authentication logic)."""
    username = StringField('Username or Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=12, message='Password must be at least 12 characters.')
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match.')
    ])
    submit = SubmitField('Reset Password')

    def validate_password(self, field):
        # Reuse RegistrationForm's password strength logic
        from forms import PasswordStrength
        score = PasswordStrength.score(field.data)
        if score < 3:
            raise ValidationError('Password is too weak. Please choose a stronger password.') 

class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('Old Password', validators=[
        DataRequired(message='Please enter your current password.')
    ])
    new_password = PasswordField('New Password', validators=[
        DataRequired(message='Please enter a new password.'),
        Length(min=12, message='Password must be at least 12 characters long.'),
        Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{12,}$',
               message='Password must include at least one uppercase letter, one lowercase letter, one number, and one special character.')
    ])
    confirm_new_password = PasswordField('Confirm New Password', validators=[
        DataRequired(message='Please confirm your new password.'),
        EqualTo('new_password', message='Passwords must match.')
    ])
    submit = SubmitField('Change Password')

    def validate_new_password(self, field):
        # Check password strength using the existing PasswordStrength class
        score = PasswordStrength.score(field.data)
        if score < 3:
            raise ValidationError('Password is too weak. Please choose a stronger password with better complexity.')
        
        # Additional validation: check for common patterns
        if re.search(r'(1234|abcd|password|qwerty|letmein|admin|user)', field.data, re.IGNORECASE):
            raise ValidationError('Password contains common patterns that are not allowed.')
        
        # Check for repeated characters
        if re.search(r'(.)\1{2,}', field.data):
            raise ValidationError('Password contains too many repeated characters.')

class TwoFAVerificationForm(FlaskForm):
    code = StringField('Verification Code', validators=[
        DataRequired(),
        Length(min=6, max=6, message='Verification code must be exactly 6 digits.')
    ])
    remember_device = BooleanField('Remember This Device (Skip 2FA for 30 days)')
    submit = SubmitField('Verify') 