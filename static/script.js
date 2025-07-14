// Password strength meter and password visibility toggle for registration form
// Security: Client-side feedback only; server-side validation is authoritative
function scorePassword(p) {
    let score = 0;
    if (!p) return 0;
    if (p.length >= 16) score += 2;
    else if (p.length >= 12) score += 1;
    if (/[A-Z]/.test(p)) score += 1;
    if (/[a-z]/.test(p)) score += 1;
    if (/\d/.test(p)) score += 1;
    if (/[^A-Za-z0-9]/.test(p)) score += 1;
    if (/(.)\1{2,}/.test(p)) score -= 1;
    if (/(1234|abcd|password|qwerty|letmein)/i.test(p)) score -= 2;
    if (/(\w{3,})\1/.test(p)) score -= 1;
    return score;
}

function labelScore(score) {
    if (score <= 1) return 'Very Weak';
    if (score === 2) return 'Weak';
    if (score === 3) return 'Good';
    if (score === 4) return 'Strong';
    return 'Very Strong';
}

// Consolidate ALL JavaScript that needs to run after the DOM is ready inside this ONE listener.
document.addEventListener('DOMContentLoaded', function () {
    // --- Password visibility toggle for all password fields (event delegation) ---
    document.body.addEventListener('click', function(e) {
        // Only handle clicks on toggle buttons with an eye icon
        if (e.target.closest('button[type="button"]') && e.target.closest('button').querySelector('i.bi-eye, i.bi-eye-slash')) {
            const btn = e.target.closest('button');
            const group = btn.closest('.input-group');
            if (!group) return;
            const input = group.querySelector('input[type="password"], input[type="text"]');
            const icon = btn.querySelector('i');
            if (input) {
                if (input.type === 'password') {
                    input.type = 'text';
                    if (icon) {
                        icon.classList.remove('bi-eye-slash');
                        icon.classList.add('bi-eye');
                    }
                } else {
                    input.type = 'password';
                    if (icon) {
                        icon.classList.remove('bi-eye');
                        icon.classList.add('bi-eye-slash');
                    }
                }
            }
        }
    });

    // --- Setup for main password field (registration form) ---
    const passwordInput = document.getElementById('password');
    const passwordStrengthMeter = document.getElementById('password-strength-meter');
    const passwordStrengthBar = document.getElementById('password-strength-bar');
    if (passwordInput && passwordStrengthMeter) {
        passwordInput.addEventListener('input', function() {
            const val = this.value;
            const score = scorePassword(val);
            const label = labelScore(score);
            let strengthText = 'Strength: ' + label;
            
            // Clear meter for empty password
            if (!val) {
                strengthText = '';
            }
            
            passwordStrengthMeter.textContent = strengthText;
            
            // Reset color classes
            passwordStrengthMeter.classList.remove('password-strength-meter-very-weak', 'password-strength-meter-weak', 'password-strength-meter-good', 'password-strength-meter-strong', 'password-strength-meter-very-strong');

            // Add new color class
            if (val) {
                passwordStrengthMeter.classList.add('password-strength-meter-' + label.toLowerCase().replace(' ', '-'));
            }

            // --- Visual bar logic ---
            if (passwordStrengthBar) {
                // Remove all color classes
                passwordStrengthBar.classList.remove('very-weak', 'weak', 'good', 'strong', 'very-strong');
                let width = '0%';
                let barClass = '';
                if (!val) {
                    passwordStrengthBar.style.width = '0%';
                    passwordStrengthBar.style.background = 'transparent';
                } else {
                    if (score <= 1) { width = '20%'; barClass = 'very-weak'; }
                    else if (score === 2) { width = '40%'; barClass = 'weak'; }
                    else if (score === 3) { width = '60%'; barClass = 'good'; }
                    else if (score === 4) { width = '80%'; barClass = 'strong'; }
                    else { width = '100%'; barClass = 'very-strong'; }
                    passwordStrengthBar.style.width = width;
                    passwordStrengthBar.classList.add(barClass);
                }
            }
        });
    }

    // --- Client-side validation (Registration Form fields) ---
    const regUsernameInput = document.getElementById('username'); // Registration only
    const regEmailInput = document.getElementById('email');
    const regPasswordInput = document.getElementById('password');
    const regConfirmPasswordInput = document.getElementById('confirm_password');

    // For password change form fields
    const oldPasswordInput = document.getElementById('old_password');
    const newPasswordInput = document.getElementById('new_password');
    const confirmNewPasswordInput = document.getElementById('confirm_new_password');

    function validateField(input, validationFn, feedbackElId) {
        const feedbackEl = document.getElementById(feedbackElId);
        const [isValid, message] = validationFn(input.value);
        if (isValid) {
            input.classList.remove('is-invalid');
            input.classList.add('is-valid');
            feedbackEl.textContent = '';
        } else {
            input.classList.remove('is-valid');
            input.classList.add('is-invalid');
            feedbackEl.textContent = message;
        }
    }

    // --- Validation Listeners for REGISTRATION FORM ---
    if (regUsernameInput) {
        regUsernameInput.addEventListener('blur', () => {
             validateField(regUsernameInput, (val) => {
                if (!val) return [false, 'Username is required.'];
                if (val.length < 4) return [false, 'Username must be at least 4 characters.'];
                if (val.length > 20) return [false, 'Username cannot exceed 20 characters.'];
                if (!/^[A-Za-z0-9_]+$/.test(val)) return [false, 'Username can only contain letters, numbers, and underscores.'];
                return [true, ''];
            }, 'username-feedback');
        });
    }
    if (regEmailInput) {
        regEmailInput.addEventListener('blur', () => {
            validateField(regEmailInput, (val) => {
                if (!val) return [false, 'Email is required.'];
                if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val)) return [false, 'Please enter a valid email address.'];
                return [true, ''];
            }, 'email-feedback');
        });
    }
    if (regPasswordInput) {
         regPasswordInput.addEventListener('blur', () => {
             validateField(regPasswordInput, (val) => {
                if (!val) return [false, 'Password is required.'];
                const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/;
                if (val.length < 12) return [false, 'Password must be at least 12 characters.'];
                if (!passwordRegex.test(val)) return [false, 'Password must contain uppercase, lowercase, number, and special character.'];
                return [true, ''];
            }, 'password-feedback');
            if (regConfirmPasswordInput && regConfirmPasswordInput.value) {
                regConfirmPasswordInput.dispatchEvent(new Event('blur'));
            }
        });
    }
    if (regConfirmPasswordInput) {
        regConfirmPasswordInput.addEventListener('blur', () => {
             validateField(regConfirmPasswordInput, (val) => {
                if (!val) return [false, 'Please confirm your password.'];
                if (val !== regPasswordInput.value) return [false, 'Passwords do not match.'];
                return [true, ''];
            }, 'confirm-password-feedback');
        });
    }

    // --- Validation Listeners for LOGIN FORM ---
    const loginUsernameInput = document.getElementById('username_or_email');
    const loginPasswordInput = document.getElementById('login_password');
    if (loginUsernameInput) {
        loginUsernameInput.addEventListener('blur', () => {
            validateField(loginUsernameInput, (val) => {
                if (!val) return [false, 'Username or email is required.'];
                if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val)) return [true, ''];
                if (/^[A-Za-z0-9_]+$/.test(val) && val.length >= 4 && val.length <= 20) return [true, ''];
                return [false, 'Please enter a valid username or email address.'];
            }, 'login-username-feedback');
        });
    }
    if (loginPasswordInput) {
        loginPasswordInput.addEventListener('blur', () => {
            validateField(loginPasswordInput, (val) => {
                if (!val) return [false, 'Password is required.'];
                const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/;
                if (val.length < 12) return [false, 'Password must be at least 12 characters.'];
                if (!passwordRegex.test(val)) return [false, 'Password must contain uppercase, lowercase, number, and special character.'];
                return [true, ''];
            }, 'login-password-feedback');
        });
    }

    // --- AJAX for Account Deletion (profile page) ---
    const confirmDeleteAccount = document.getElementById('confirmDeleteAccount');
    if (confirmDeleteAccount) {
        confirmDeleteAccount.addEventListener('click', function() {
            // Get CSRF token for AJAX calls
            const csrfToken = document.querySelector('meta[name=csrf-token]')?.content || document.cookie.match(/csrftoken=([^;]+)/)?.[1] || '';

            fetch('/delete_account', {
                method: 'POST',
                headers: { 
                    'X-CSRFToken': csrfToken,
                    'Content-Type': 'application/json'
                },
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    window.location.href = data.redirect_url;
                } else {
                    // Remove alert pop-up, just show in-page error if needed
                    // Optionally, you can show an in-page error message here if you want
                    // For now, do nothing (no alert)
                }
            })
            .catch(error => {
                console.error('Error:', error);
                // Remove alert pop-up, just show in-page error if needed
                // For now, do nothing (no alert)
            });
        });
    }

    // --- AJAX for Logout Others (profile page) ---
    const confirmLogoutOthers = document.getElementById('confirmLogoutOthers');
    if (confirmLogoutOthers) {
        confirmLogoutOthers.addEventListener('click', function() {
            // Get CSRF token for AJAX calls
            const csrfToken = document.querySelector('meta[name=csrf-token]')?.content || document.cookie.match(/csrftoken=([^;]+)/)?.[1] || '';

            fetch('/logout_others', {
                method: 'POST',
                headers: { 
                    'X-CSRFToken': csrfToken,
                    'Content-Type': 'application/json'
                },
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Close modal
                    const modal = bootstrap.Modal.getInstance(document.getElementById('logoutOthersModal'));
                    if (modal) modal.hide();

                    // Display success message
                    const alertDiv = document.createElement('div');
                    alertDiv.className = 'alert alert-success alert-dismissible fade show mt-3';
                    alertDiv.innerHTML = `
                        <i class="bi bi-check-circle me-2"></i>${data.message}
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    `;
                    
                    // Insert after the main profile card, or at the top of the container
                    const profileCard = document.querySelector('.card.glass-card.shadow-lg');
                    if (profileCard) {
                        profileCard.parentNode.insertBefore(alertDiv, profileCard.nextSibling);
                    } else {
                        // Fallback: insert at the top of the container
                        document.querySelector('.container').insertBefore(alertDiv, document.querySelector('.container').firstChild);
                    }

                    // Optional: Remove alert after a few seconds
                    setTimeout(() => {
                        alertDiv.remove();
                    }, 5000);
                } else {
                    // This should not happen since backend always returns success: True
                    console.error('Unexpected response:', data);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                // Show error message without alert popup
                const alertDiv = document.createElement('div');
                alertDiv.className = 'alert alert-danger alert-dismissible fade show mt-3';
                alertDiv.innerHTML = `
                    <i class="bi bi-exclamation-triangle me-2"></i>An error occurred while ending other sessions.
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                `;
                
                const profileCard = document.querySelector('.card.glass-card.shadow-lg');
                if (profileCard) {
                    profileCard.parentNode.insertBefore(alertDiv, profileCard.nextSibling);
                } else {
                    document.querySelector('.container').insertBefore(alertDiv, document.querySelector('.container').firstChild);
                }
            });
        });
    }

    // --- AJAX for Disable 2FA (profile page) ---
    const confirmDisable2FA = document.getElementById('confirmDisable2FA');
    if (confirmDisable2FA) {
        confirmDisable2FA.addEventListener('click', function() {
            const csrfToken = document.querySelector('meta[name=csrf-token]')?.content || document.cookie.match(/csrftoken=([^;]+)/)?.[1] || ''; // More robust CSRF token retrieval

            fetch('/profile/2fa/disable', {
                method: 'POST',
                headers: { 'X-CSRFToken': csrfToken },
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Close modal and reload page to show updated 2FA status
                    const modal = bootstrap.Modal.getInstance(document.getElementById('disable2FAModal'));
                    if (modal) modal.hide(); // Check if modal exists before hiding
                    
                    // Show success message and reload page
                    const alertDiv = document.createElement('div');
                    alertDiv.className = 'alert alert-success alert-dismissible fade show';
                    alertDiv.innerHTML = `
                        <i class="bi bi-check-circle me-2"></i>${data.message}
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    `;
                    document.querySelector('.container').insertBefore(alertDiv, document.querySelector('.container').firstChild);
                    
                    // Reload page after a short delay to show updated status
                    setTimeout(() => {
                        window.location.reload();
                    }, 1500);
                } else {
                    alert(data.message || 'Failed to disable 2FA.');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('An error occurred while disabling 2FA.');
            });
        });
    }

    // Optional: Simple table sort for login log (by timestamp)
    const loginLogTable = document.getElementById('loginLogTable');
    if (loginLogTable) {
        loginLogTable.querySelectorAll('th').forEach((th, idx) => {
            th.style.cursor = 'pointer';
            th.addEventListener('click', function() {
                const rows = Array.from(loginLogTable.querySelectorAll('tbody tr'));
                const asc = th.classList.toggle('asc');
                rows.sort((a, b) => {
                    const aText = a.children[idx].textContent.trim();
                    const bText = b.children[idx].textContent.trim();
                    if (idx === 0) { // Timestamp
                        return asc ? aText.localeCompare(bText) : bText.localeCompare(aText);
                    }
                    return asc ? aText.localeCompare(bText) : bText.localeCompare(aText);
                });
                rows.forEach(row => loginLogTable.querySelector('tbody').appendChild(row));
            });
        });
    }

    // Handle tab navigation from URL hash (e.g., /profile#password)
    const hash = window.location.hash;
    if (hash) {
        const tab = document.querySelector(`[data-bs-target="${hash}"]`);
        if (tab) {
            const tabInstance = new bootstrap.Tab(tab);
            tabInstance.show();
            // Scroll to the top of the tab content if needed
            document.querySelector(hash).scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    }

    // --- Quick Actions Button Functionality (Click listeners for Overview tab buttons) ---
    // Target buttons that toggle Bootstrap tabs
    const quickActionButtons = document.querySelectorAll('#overview a[data-bs-toggle="tab"]');
    quickActionButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault(); // Prevent default anchor behavior (page jump)

            const targetTabId = this.getAttribute('data-bs-target'); // e.g., '#password'

            if (targetTabId) {
                // Find the corresponding tab *button* in the main nav-tabs
                const tabButton = document.querySelector(`[data-bs-target="${targetTabId}"]`);

                if (tabButton) {
                    // Activate the tab
                    const tabInstance = new bootstrap.Tab(tabButton);
                    tabInstance.show(); 

                    // Optional: Scroll to top of the tab content after activation
                    // Wait briefly for tab to become visible before scrolling
                    setTimeout(() => {
                        const targetContent = document.querySelector(targetTabId);
                        if (targetContent) {
                            targetContent.scrollIntoView({ behavior: 'smooth', block: 'start' });
                        }
                    }, 100); // Small delay to allow tab content to become active
                } else {
                    console.error('Target tab button not found for:', targetTabId);
                }
            }
        });
    });

    // --- Specific Event Listeners for Password Strength Meter on Profile (New Password) ---
    const newPasswordProfileInput = document.getElementById('new_password');
    const changePasswordStrengthMeter = document.getElementById('password-strength-meter-profile'); // Updated to unique ID

    // Ensure the strength meter in profile.html has a unique ID, e.g., 'password-strength-meter-profile'
    // And update the JavaScript to target that unique ID
    
    if (newPasswordProfileInput && changePasswordStrengthMeter) {
        newPasswordProfileInput.addEventListener('input', function() {
            const val = this.value;
            const score = scorePassword(val);
            const label = labelScore(score);
            
            if (!val) {
                changePasswordStrengthMeter.textContent = '';
                changePasswordStrengthMeter.className = 'form-text';
                return;
            }
            
            changePasswordStrengthMeter.textContent = 'Strength: ' + label;
            changePasswordStrengthMeter.className = 'password-strength-meter ' + label.toLowerCase().replace(' ', '-');
        });
    }

    // Button ripple effect for .btn-cool and .btn-glass
    function addRippleEffect(e) {
        const button = e.currentTarget;
        const circle = document.createElement('span');
        circle.classList.add('ripple');
        const diameter = Math.max(button.clientWidth, button.clientHeight);
        const radius = diameter / 2;
        const rect = button.getBoundingClientRect();
        circle.style.width = circle.style.height = `${diameter}px`;
        circle.style.left = `${e.clientX - rect.left - radius}px`;
        circle.style.top = `${e.clientY - rect.top - radius}px`;
        button.appendChild(circle);
        // Remove existing ripples to prevent accumulation
        const existingRipples = button.getElementsByClassName('ripple');
        if (existingRipples.length > 1) {
            Array.from(existingRipples).slice(0, existingRipples.length - 1).forEach(r => r.remove());
        }
        setTimeout(() => circle.remove(), 500);
    }

    // Add ripple effect to cool buttons
    const coolButtons = document.querySelectorAll('.btn-cool, .btn-hero, .btn-primary, .btn-secondary, .btn-outline-primary, .btn-outline-info, .btn-outline-warning, .btn-outline-danger');
    coolButtons.forEach(button => {
        button.addEventListener('click', addRippleEffect);
    });

});