// Modern Notification and Modal System

class NotificationManager {
  constructor() {
    this.container = null;
    this.init();
  }

  init() {
    // Create notification container
    this.container = document.createElement('div');
    this.container.className = 'notification-container';
    document.body.appendChild(this.container);
  }

  show(message, type = 'info', title = '', duration = 5000) {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    
    const icons = {
      success: `<svg class="notification-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="color: #10b981;">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
      </svg>`,
      error: `<svg class="notification-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="color: #ef4444;">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
      </svg>`,
      warning: `<svg class="notification-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="color: #f59e0b;">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"></path>
      </svg>`,
      info: `<svg class="notification-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="color: #dc2626;">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
      </svg>`
    };

    notification.innerHTML = `
      ${icons[type] || icons.info}
      <div class="notification-content">
        ${title ? `<div class="notification-title">${title}</div>` : ''}
        <div class="notification-message">${message}</div>
      </div>
      <button class="notification-close">
        <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
        </svg>
      </button>
    `;

    // Add close functionality
    const closeBtn = notification.querySelector('.notification-close');
    closeBtn.addEventListener('click', () => this.remove(notification));

    // Add to container
    this.container.appendChild(notification);

    // Animate in
    setTimeout(() => notification.classList.add('show'), 100);

    // Auto remove
    if (duration > 0) {
      setTimeout(() => this.remove(notification), duration);
    }

    return notification;
  }

  remove(notification) {
    notification.classList.remove('show');
    setTimeout(() => {
      if (notification.parentNode) {
        notification.parentNode.removeChild(notification);
      }
    }, 300);
  }

  success(message, title = 'Success') {
    return this.show(message, 'success', title);
  }

  error(message, title = 'Error') {
    return this.show(message, 'error', title);
  }

  warning(message, title = 'Warning') {
    return this.show(message, 'warning', title);
  }

  info(message, title = 'Info') {
    return this.show(message, 'info', title);
  }
}

class ModalManager {
  constructor() {
    this.currentModal = null;
  }

  show(options) {
    return new Promise((resolve, reject) => {
      // Remove existing modal
      this.close();

      const overlay = document.createElement('div');
      overlay.className = 'modal-overlay';

      const modal = document.createElement('div');
      modal.className = 'modal';

      const iconMap = {
        success: `<svg width="24" height="24" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="color: #10b981;">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
        </svg>`,
        error: `<svg width="24" height="24" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="color: #ef4444;">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
        </svg>`,
        warning: `<svg width="24" height="24" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="color: #f59e0b;">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"></path>
        </svg>`,
        question: `<svg width="24" height="24" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="color: #dc2626;">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
        </svg>`
      };

      modal.innerHTML = `
        <div class="modal-header">
          <div class="modal-title">
            ${options.icon ? iconMap[options.icon] || '' : ''}
            ${options.title || 'Confirm'}
          </div>
          <button class="modal-close">
            <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
            </svg>
          </button>
        </div>
        <div class="modal-body">
          <div class="modal-message">${options.message || ''}</div>
          ${options.input ? `<input type="text" class="modal-input" placeholder="${options.placeholder || ''}" value="${options.defaultValue || ''}">` : ''}
          <div class="modal-error" style="color: #ef4444; font-size: 0.875rem; margin-bottom: 1rem; display: none;"></div>
          <div class="modal-actions">
            ${options.showCancel !== false ? `<button class="modal-button secondary" data-action="cancel">${window.getTranslation ? window.getTranslation('Cancel') : 'Cancel'}</button>` : ''}
            <button class="modal-button ${options.type === 'danger' ? 'danger' : 'primary'}" data-action="confirm">
              ${options.confirmText || (window.getTranslation ? window.getTranslation('OK') : 'OK')}
            </button>
          </div>
        </div>
      `;

      overlay.appendChild(modal);
      document.body.appendChild(overlay);
      this.currentModal = overlay;

      // Event listeners
      const closeBtn = modal.querySelector('.modal-close');
      const cancelBtn = modal.querySelector('[data-action="cancel"]');
      const confirmBtn = modal.querySelector('[data-action="confirm"]');
      const input = modal.querySelector('.modal-input');
      const errorMsg = modal.querySelector('.modal-error');

      const cleanup = () => {
        overlay.classList.remove('show');
        setTimeout(() => {
          if (overlay.parentNode) {
            overlay.parentNode.removeChild(overlay);
          }
          this.currentModal = null;
        }, 300);
      };

      closeBtn.addEventListener('click', () => {
        cleanup();
        resolve(false);
      });

      if (cancelBtn) {
        cancelBtn.addEventListener('click', () => {
          cleanup();
          resolve(false);
        });
      }

      if (input) {
        input.addEventListener('input', () => {
          if (errorMsg) errorMsg.style.display = 'none';
          input.style.borderColor = '';
        });

        input.addEventListener('keypress', (e) => {
          if (e.key === 'Enter') {
            confirmBtn.click();
          }
        });
      }

      confirmBtn.addEventListener('click', () => {
        if (options.input && options.required && input && !input.value.trim()) {
          if (errorMsg) {
            const currentLang = localStorage.getItem('language') || 'en';
            const errorText = currentLang === 'my' 
              ? 'ကျေးဇူးပြု၍ content title ထည့်ပေးပါ' 
              : 'Please enter content title';
            
            errorMsg.textContent = window.getTranslation ? window.getTranslation(errorText) : errorText;
            errorMsg.style.display = 'block';
          }
          input.style.borderColor = '#ef4444';
          input.focus();
          return;
        }

        const result = options.input ? input.value : true;
        cleanup();
        resolve(result);
      });

      // Close on overlay click
      overlay.addEventListener('click', (e) => {
        if (e.target === overlay) {
          cleanup();
          resolve(false);
        }
      });

      // Show modal
      setTimeout(() => overlay.classList.add('show'), 100);

      // Focus input if present
      if (input) {
        setTimeout(() => input.focus(), 400);
      }
    });
  }

  close() {
    if (this.currentModal) {
      this.currentModal.classList.remove('show');
      setTimeout(() => {
        if (this.currentModal && this.currentModal.parentNode) {
          this.currentModal.parentNode.removeChild(this.currentModal);
        }
        this.currentModal = null;
      }, 300);
    }
  }

  confirm(message, title = 'Confirm', options = {}) {
    return this.show({
      title,
      message,
      icon: 'question',
      type: options.type || 'primary',
      confirmText: options.confirmText || 'Yes',
      ...options
    });
  }

  alert(message, title = 'Alert', type = 'info') {
    return this.show({
      title,
      message,
      icon: type,
      showCancel: false,
      confirmText: window.getTranslation ? window.getTranslation('OK') : 'OK'
    });
  }

  prompt(message, title = 'Input', defaultValue = '', placeholder = '', options = {}) {
    return this.show({
      title,
      message,
      input: true,
      defaultValue,
      placeholder,
      icon: 'question',
      ...options
    });
  }
}

// Global instances
const notify = new NotificationManager();
const modal = new ModalManager();

// Export for global use
window.notify = notify;
window.modal = modal;

// Override default alert, confirm, prompt
window.showAlert = (message, title, type) => modal.alert(message, title, type);
window.showConfirm = (message, title, options) => modal.confirm(message, title, options);
window.showPrompt = (message, title, defaultValue, placeholder) => modal.prompt(message, title, defaultValue, placeholder);
