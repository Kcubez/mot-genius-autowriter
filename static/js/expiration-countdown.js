// Expiration Countdown Timer
class ExpirationCountdown {
  constructor() {
    this.desktopElement = document.getElementById('expiration-countdown-desktop');
    this.mobileElement = document.getElementById('expiration-countdown-mobile');
    this.interval = null;
    
    if (this.desktopElement || this.mobileElement) {
      this.init();
    }
  }

  init() {
    // Get expiration date from data attribute
    const expirationISO = this.desktopElement?.dataset.expiration || this.mobileElement?.dataset.expiration;
    
    if (!expirationISO) {
      // No expiration date, show N/A
      this.updateDisplay('N/A');
      return;
    }

    this.expirationDate = new Date(expirationISO);
    
    // Check if date is valid
    if (isNaN(this.expirationDate.getTime())) {
      this.updateDisplay('N/A');
      return;
    }

    // Start countdown
    this.updateCountdown();
    this.interval = setInterval(() => this.updateCountdown(), 1000);
  }

  updateCountdown() {
    const now = new Date();
    const diff = this.expirationDate - now;

    // If expired
    if (diff <= 0) {
      this.updateDisplay('Expired');
      clearInterval(this.interval);
      // Optionally redirect to logout or show expired message
      setTimeout(() => {
        window.location.href = '/logout';
      }, 2000);
      return;
    }

    // Calculate time remaining
    const hours = Math.floor(diff / (1000 * 60 * 60));
    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
    const seconds = Math.floor((diff % (1000 * 60)) / 1000);

    // Format as HH:MM:SS
    const timeString = `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
    
    this.updateDisplay(timeString);
  }

  updateDisplay(timeString) {
    // Update desktop countdown
    if (this.desktopElement) {
      const timerSpan = this.desktopElement.querySelector('.countdown-timer');
      if (timerSpan) {
        timerSpan.textContent = timeString;
      }
    }

    // Update mobile countdown
    if (this.mobileElement) {
      const timerSpan = this.mobileElement.querySelector('.countdown-timer');
      if (timerSpan) {
        timerSpan.textContent = timeString;
      }
    }
  }
}

// Initialize countdown when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
  new ExpirationCountdown();
});
