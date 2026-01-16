// Expiration Countdown Timer (Production - Normal Users Only)
class ExpirationCountdown {
  constructor() {
    this.desktopElement = document.getElementById('expiration-countdown-desktop');
    this.mobileElement = document.getElementById('expiration-countdown-mobile');
    this.interval = null;
    this.currentLang = localStorage.getItem('language') || 'my';
    
    if (this.desktopElement || this.mobileElement) {
      this.init();
      this.setupLanguageListener();
    }
  }

  setupLanguageListener() {
    // Listen for language changes
    window.addEventListener('storage', (e) => {
      if (e.key === 'language' && e.newValue !== this.currentLang) {
        this.currentLang = e.newValue;
        this.updateCountdown(); // Update display with new language
      }
    });
    
    // Also listen for custom language change event (for same-tab changes)
    window.addEventListener('languageChanged', (e) => {
      if (e.detail && e.detail.language !== this.currentLang) {
        this.currentLang = e.detail.language;
        this.updateCountdown(); // Update display with new language
      }
    });
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

    // If expired - show user-friendly message based on language (normal user only)
    if (diff <= 0) {
      // Use current language from instance
      const expiredMessages = {
        en: 'Your account is expired',
        my: 'သင်၏ account သက်တမ်းကုန်ဆုံးသွားပါပြီ'
      };
      
      const expiredText = expiredMessages[this.currentLang] || expiredMessages['my'];
      this.updateDisplay(expiredText, true); // Pass true to indicate expired
      
      // Stop updating once expired
      if (this.interval) {
        clearInterval(this.interval);
        this.interval = null;
      }
      return;
    }

    // Calculate time remaining
    const days = Math.floor(diff / (1000 * 60 * 60 * 24));
    const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
    const seconds = Math.floor((diff % (1000 * 60)) / 1000);

    // Format based on time remaining
    let timeString;
    if (days > 0) {
      timeString = `${days}d ${hours}h ${minutes}m`;
    } else if (hours > 0) {
      timeString = `${hours}h ${minutes}m ${seconds}s`;
    } else if (minutes > 0) {
      timeString = `${minutes}m ${seconds}s`;
    } else {
      timeString = `${seconds}s`;
    }
    
    this.updateDisplay(timeString);
  }

  updateDisplay(timeString, isExpired = false) {
    // Update desktop countdown
    if (this.desktopElement) {
      const timerSpan = this.desktopElement.querySelector('.countdown-timer');
      if (timerSpan) {
        timerSpan.textContent = timeString;
      }
      
      // Hide/show "Expires in:" prefix based on expiration status
      if (isExpired) {
        // Replace entire text content to remove "Expires in:"
        this.desktopElement.innerHTML = `<span class="countdown-timer">${timeString}</span>`;
      }
    }

    // Update mobile countdown
    if (this.mobileElement) {
      const timerSpan = this.mobileElement.querySelector('.countdown-timer');
      if (timerSpan) {
        timerSpan.textContent = timeString;
      }
      
      // Hide/show "Expires in:" prefix based on expiration status
      if (isExpired) {
        // Replace entire text content to remove "Expires in:"
        this.mobileElement.innerHTML = `<span class="countdown-timer">${timeString}</span>`;
      }
    }
  }
}

// Initialize countdown when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
  new ExpirationCountdown();
});
