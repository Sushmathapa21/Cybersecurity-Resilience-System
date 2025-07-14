# Secure User Registration Prototype

This project is a secure user registration web application prototype, designed for an Advanced Cyber Security academic assignment. It demonstrates robust security principles and best practices in user data protection.

## Features

- **User Registration UI:** Clean, responsive web interface with fields for username, password, and CAPTCHA.
- **Password Strength Meter:** Real-time feedback as you type, with server-side enforcement of strong password policies.
- **Password Visibility Toggle:** Easily show/hide your password with an eye icon for better usability.
- **Password Hashing:** Passwords are hashed using bcrypt with a salt; never stored in plain text.
- **Password History:** Prevents reuse of the last 3 passwords for each user.
- **Image CAPTCHA:** Distorted text image CAPTCHA (with refresh) to prevent automated/bot registrations, generated using Pillow.
- **Input Validation:** Comprehensive server-side validation for all fields.
- **CSRF Protection:** All forms are protected against CSRF attacks.
- **Error Handling:** Secure, user-friendly error messages with no sensitive information leakage.
- **Registration Success Page:** Clear confirmation and next steps after successful registration.
- **Login/Register Flow:** Distinct, modern pages for registration and login, with clear navigation between them.
- **Modern UI/UX:** Bootstrap 5, custom CSS, and JavaScript for a visually appealing, accessible, and responsive experience.
- **Code Comments:** Security design choices are explained throughout the code.

## Password Strength Criteria

Passwords are evaluated using a scoring system based on:
- **Length:** Minimum 12 characters (16+ recommended for best score).
- **Character Variety:** Must include uppercase, lowercase, numbers, and special characters.
- **Pattern Avoidance:** Penalizes common patterns (e.g., '1234', 'password'), repeated characters, and dictionary words.
- **No Repetition:** Prevents use of the last 3 passwords.

**Feedback is provided in real-time** as you type, but server-side validation is authoritative.

## CAPTCHA Type and Justification

A **distorted text image CAPTCHA** is used. This is generated using Pillow, with random alphanumeric strings, distortions, and noise to prevent automated solving. The image is refreshed on demand and validated server-side. This approach is more robust than simple math CAPTCHAs and demonstrates advanced human verification.

## Security Principles Applied

- **Password Hashing:** Uses bcrypt with salt for strong, adaptive hashing.
- **No Plain-Text Storage:** Passwords are never stored or logged in plain text.
- **Input Validation:** All user input is validated server-side to prevent SQL injection, XSS, and other attacks.
- **CSRF Protection:** Flask-WTF provides CSRF tokens for all forms.
- **Session Security:** Secure cookies, HTTPOnly, and SameSite flags are set.
- **Image CAPTCHA:** Prevents automated registrations using distorted images and secure randoms.
- **Password Visibility Toggle:** Implemented securely with JavaScript, does not expose password in logs or network.
- **Error Handling:** No sensitive information is revealed in error messages.
- **Security by Design:** Code is modular, well-commented, and avoids common pitfalls (e.g., hardcoded secrets, client-only validation).
- **HTTPS:** While not enabled in this prototype, all credentials should be transmitted over HTTPS in production (see code comments).

## Setup Instructions

1. **Clone the repository:**
   ```
   git clone <repo-url>
   cd "ACS prototype"
   ```
2. **Create a virtual environment and activate it:**
   ```
   python3 -m venv venv
   source venv/bin/activate
   ```
3. **Install dependencies:**
   ```
   pip install -r requirements.txt
   ```
   (This will install Flask, Flask-WTF, Flask-SQLAlchemy, WTForms, bcrypt, and Pillow)
4. **Run the application:**
   ```
   flask run
   ```
   The app will be available at [http://127.0.0.1:5000](http://127.0.0.1:5000)

## Notes
- For demonstration, the database is SQLite and stored in the `instance/` folder.
- CAPTCHA images are stored in the `captcha_images/` folder and are deleted after use for security and privacy.
- In production, always use HTTPS to protect data in transit.
- For a full system, implement secure session management, account lockout, email verification, and logging.

---

**This prototype is designed to demonstrate excellent secure coding practices for academic purposes.** 