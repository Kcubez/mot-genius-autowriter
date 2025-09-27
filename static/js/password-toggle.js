// Password Toggle Functionality

class PasswordToggle {
  constructor(container) {
    this.container = container;
    this.passwordInput = container.querySelector('.password-input');
    this.toggleBtn = container.querySelector('.password-toggle-btn');
    this.isVisible = false;
    
    this.init();
  }
  
  init() {
    if (!this.passwordInput || !this.toggleBtn) return;
    
    // Add click event listener
    this.toggleBtn.addEventListener('click', (e) => {
      e.preventDefault();
      this.toggleVisibility();
    });
    
    // Add keyboard support
    this.toggleBtn.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        this.toggleVisibility();
      }
    });
    
    // Add password strength indicator if needed
    if (this.passwordInput.id === 'password' && this.container.closest('.create-user-form')) {
      this.addPasswordStrengthIndicator();
    }
  }
  
  toggleVisibility() {
    this.isVisible = !this.isVisible;
    
    // Toggle input type
    this.passwordInput.type = this.isVisible ? 'text' : 'password';
    
    // Toggle button class
    this.toggleBtn.classList.toggle('password-visible', this.isVisible);
    
    // Update aria-label for accessibility
    const label = this.isVisible ? 'Hide password' : 'Show password';
    this.toggleBtn.setAttribute('aria-label', label);
    
    // Focus back to input
    this.passwordInput.focus();
  }
  
  addPasswordStrengthIndicator() {
    const strengthIndicator = document.createElement('div');
    strengthIndicator.className = 'password-strength';
    strengthIndicator.id = 'password-strength';
    
    this.container.parentNode.insertBefore(strengthIndicator, this.container.nextSibling);
    
    this.passwordInput.addEventListener('input', () => {
      this.updatePasswordStrength(strengthIndicator);
    });
  }
  
  updatePasswordStrength(indicator) {
    const password = this.passwordInput.value;
    const strength = this.calculatePasswordStrength(password);
    
    indicator.className = `password-strength ${strength.level}`;
    indicator.textContent = strength.message;
  }
  
  calculatePasswordStrength(password) {
    if (password.length === 0) {
      return { level: '', message: '' };
    }
    
    let score = 0;
    
    // Length check
    if (password.length >= 8) score += 1;
    if (password.length >= 12) score += 1;
    
    // Character variety
    if (/[a-z]/.test(password)) score += 1;
    if (/[A-Z]/.test(password)) score += 1;
    if (/[0-9]/.test(password)) score += 1;
    if (/[^A-Za-z0-9]/.test(password)) score += 1;
    
    if (score <= 2) {
      return { level: 'weak', message: 'Weak password - consider adding more characters and variety' };
    } else if (score <= 4) {
      return { level: 'medium', message: 'Medium strength - good but could be stronger' };
    } else {
      return { level: 'strong', message: 'Strong password!' };
    }
  }
}

// Initialize password toggles when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
  const passwordContainers = document.querySelectorAll('.password-input-container');
  
  passwordContainers.forEach(container => {
    new PasswordToggle(container);
  });
});

// Handle failed login attempts display
function displayLoginAttempts(attempts) {
  const loginForm = document.querySelector('.login-form');
  if (!loginForm) return;
  
  // Remove existing warning
  const existingWarning = loginForm.querySelector('.login-attempts-warning');
  if (existingWarning) {
    existingWarning.remove();
  }
  
  if (attempts > 0) {
    const remaining = 3 - attempts;
    const warningDiv = document.createElement('div');
    warningDiv.className = `login-attempts-warning ${attempts >= 2 ? 'critical' : ''}`;
    
    if (attempts >= 3) {
      warningDiv.innerHTML = `
        <strong>Account Locked!</strong><br>
        Your account has been deactivated due to multiple failed login attempts.
        Please contact an administrator to reactivate your account.
      `;
    } else {
      warningDiv.innerHTML = `
        <strong>Warning:</strong> ${attempts} failed login attempt${attempts > 1 ? 's' : ''}.
        ${remaining} attempt${remaining > 1 ? 's' : ''} remaining before account deactivation.
      `;
    }
    
    loginForm.insertBefore(warningDiv, loginForm.firstChild);
  }
}

// Export for global use
window.PasswordToggle = PasswordToggle;
window.displayLoginAttempts = displayLoginAttempts;
