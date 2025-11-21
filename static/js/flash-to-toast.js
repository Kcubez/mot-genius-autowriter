// Flash Messages to Toast Converter
document.addEventListener('DOMContentLoaded', function() {
  // Wait a bit for notifications.js to load
  setTimeout(() => {
    // Test if notify is working
    if (!window.notify) {
      return;
    }
    
    // Check for flash messages data attribute
    const flashData = document.querySelector('[data-flash-messages]');
    
    if (flashData) {
      try {
        const messagesData = flashData.getAttribute('data-flash-messages');
        
        if (!messagesData) {
          return;
        }
        
        const messages = JSON.parse(messagesData);
        
        if (messages && messages.length > 0) {
          messages.forEach(([category, message], index) => {
            // Add a small delay between messages to avoid overlap
            setTimeout(() => {
              processMessage(category, message);
            }, index * 100);
          });
        }
      } catch (e) {
        // Silent error handling
      }
    }
  }, 300);
});

function processMessage(category, message) {
  if (typeof window.notify === 'undefined') {
    return;
  }
  
  switch(category) {
    case 'error':
      if (message.includes('Invalid username or password') || message.includes('Invalid password')) {
        window.notify.error(message, '🔐 Login Failed');
      } else if (message.includes('Account is temporarily locked')) {
        window.notify.error(message, '🔒 Account Locked');
      } else if (message.includes('Account deactivated')) {
        window.notify.error(message, '❌ Account Deactivated');
      } else if (message.includes('Username already exists')) {
        window.notify.error(message, '👤 User Creation Failed');
      } else if (message.includes('trial account has expired')) {
        window.notify.show(message, 'error', '⏰ Trial Expired', 8000);
      } else if (message.includes('subscription has expired')) {
        window.notify.show(message, 'error', '📅 Subscription Expired', 8000);
      } else if (message.includes('account has expired')) {
        window.notify.show(message, 'error', '⏰ Account Expired', 8000);
      } else {
        window.notify.error(message, '❌ Error');
      }
      break;
    case 'success':
      if (message.includes('Welcome back')) {
        window.notify.success(message, '🎉 Login Successful');
      } else if (message.includes('Goodbye') && message.includes('logged out')) {
        window.notify.success(message, '👋 Logout Successful');
      } else if (message.includes('created successfully')) {
        window.notify.success(message, '✅ User Created');
      } else if (message.includes('Content saved successfully')) {
        window.notify.success(message, '💾 Content Saved');
      } else if (message.includes('Content updated successfully')) {
        window.notify.success(message, '📝 Content Updated');
      } else if (message.includes('Content deleted successfully')) {
        window.notify.success(message, '🗑️ Content Deleted');
      } else {
        window.notify.success(message, '✅ Success');
      }
      break;
    case 'warning':
      window.notify.warning(message, '⚠️ Warning');
      break;
    case 'info':
      window.notify.info(message, 'ℹ️ Information');
      break;
    default:
      window.notify.info(message, 'ℹ️ Information');
  }
}
