// Flash Messages to Toast Converter
document.addEventListener('DOMContentLoaded', function() {
  console.log('Flash-to-toast script loaded');
  
  // Wait a bit for notifications.js to load
  setTimeout(() => {
    // Test if notify is working
    if (window.notify) {
      console.log('Notify system is available');
    } else {
      console.error('Notify system not available');
      return;
    }
    
    // Check for flash messages data attribute
    const flashData = document.querySelector('[data-flash-messages]');
    console.log('Flash data element:', flashData);
    
    if (flashData) {
      try {
        const messagesData = flashData.getAttribute('data-flash-messages');
        console.log('Raw flash messages data:', messagesData);
        
        if (!messagesData) {
          console.log('No flash messages data found');
          return;
        }
        
        const messages = JSON.parse(messagesData);
        console.log('Parsed flash messages:', messages);
        console.log('Number of messages:', messages.length);
        
        if (messages && messages.length > 0) {
          messages.forEach(([category, message], index) => {
            console.log(`Processing message ${index + 1}:`, category, message);
            // Add a small delay between messages to avoid overlap
            setTimeout(() => {
              processMessage(category, message);
            }, index * 100);
          });
        } else {
          console.log('Messages array is empty');
        }
      } catch (e) {
        console.error('Error parsing flash messages:', e);
        console.error('Raw data that failed to parse:', flashData.getAttribute('data-flash-messages'));
      }
    } else {
      console.log('No flash messages element found');
    }
  }, 300);
});

function processMessage(category, message) {
  console.log('Processing message with notify:', category, message);
  
  if (typeof window.notify === 'undefined') {
    console.error('Notify object not available');
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
