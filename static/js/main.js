// Content Manager - Main JavaScript File

// Simple JavaScript for interactive elements
async function confirmDelete(message) {
  return await modal.confirm(
    message || 'Are you sure you want to delete this item?',
    'Confirm Delete',
    { type: 'danger', confirmText: 'Delete' }
  );
}

// Mobile menu toggle
function toggleMobileMenu() {
  const mobileMenu = document.getElementById('mobileMenu');
  if (mobileMenu.classList.contains('hidden')) {
    mobileMenu.classList.remove('hidden');
  } else {
    mobileMenu.classList.add('hidden');
  }
}

// Close mobile menu when clicking outside
document.addEventListener('click', function (event) {
  const mobileMenu = document.getElementById('mobileMenu');
  const mobileButton = event.target.closest('[onclick="toggleMobileMenu()"]');

  if (!mobileButton && !mobileMenu.contains(event.target)) {
    mobileMenu.classList.add('hidden');
  }
});

// Toggle user status (Admin function)
async function toggleUserStatus(userId) {
  const button = document.querySelector(`[data-action="toggle-user"][data-user-id="${userId}"]`);
  const userRow = button.closest('tr');
  // Find the status badge in the Status column (3rd td element)
  const statusCell = userRow.querySelectorAll('td')[2]; // Status is the 3rd column (index 2)
  const statusBadge = statusCell.querySelector('.inline-flex');

  // Get the action from the button text (which is correct)
  const buttonText = button.textContent.trim();
  const action = buttonText.toLowerCase(); // "deactivate" or "activate"
  const actionTitle = action.charAt(0).toUpperCase() + action.slice(1);

  const confirmed = await modal.confirm(
    `Are you sure you want to ${action} this user?`,
    `${actionTitle} User`,
    { confirmText: actionTitle }
  );

  if (confirmed) {
    // Show loading state
    button.disabled = true;
    button.textContent = 'Processing...';

    try {
      const response = await fetch(`/admin/users/${userId}/toggle`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      const data = await response.json();

      if (data.success) {
        notify.success(data.message || 'User status updated successfully');

        // Update the status badge and button text without reloading
        if (data.new_status) {
          // User is now active
          statusBadge.className =
            'inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-green-100 text-green-800';
          statusBadge.textContent = 'Active';
          button.textContent = 'Deactivate';
          button.className = 'text-indigo-600 hover:text-indigo-900';
        } else {
          // User is now inactive
          statusBadge.className =
            'inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-red-100 text-red-800';
          statusBadge.textContent = 'Inactive';
          button.textContent = 'Activate';
          button.className = 'text-green-600 hover:text-green-900';
        }
      } else {
        notify.error(data.error || 'An error occurred', 'Update Failed');
        button.textContent = buttonText; // Restore original button text
      }
    } catch (error) {
      console.error('Error:', error);
      notify.error('An error occurred while updating user status', 'Network Error');
      button.textContent = buttonText; // Restore original button text
    } finally {
      button.disabled = false;
    }
  }
}

// Reset user failed login attempts (Admin function)
async function resetUserAttempts(userId) {
  const confirmed = await modal.confirm(
    'Are you sure you want to reset the failed login attempts for this user? This will also reactivate their account if it was locked.',
    'Reset Failed Login Attempts',
    { confirmText: 'Reset Attempts' }
  );

  if (confirmed) {
    try {
      const response = await fetch(`/admin/users/${userId}/reset-attempts`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      const data = await response.json();

      if (data.success) {
        notify.success(data.message || 'Failed login attempts reset successfully');
        setTimeout(() => location.reload(), 1000);
      } else {
        notify.error(data.error || 'An error occurred', 'Reset Failed');
      }
    } catch (error) {
      console.error('Error:', error);
      notify.error('An error occurred while resetting failed login attempts', 'Network Error');
    }
  }
}

// Delete user function (Admin function)
async function deleteUser(userId) {
  const confirmed = await modal.confirm(
    'Are you sure you want to delete this user? This action cannot be undone.',
    'Delete User',
    { type: 'danger', confirmText: 'Delete User' }
  );

  if (confirmed) {
    try {
      const response = await fetch(`/admin/users/${userId}/delete`, {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      const data = await response.json();

      if (data.success) {
        notify.success('User deleted successfully');
        setTimeout(() => location.reload(), 1000);
      } else {
        notify.error(data.error || 'An error occurred', 'Delete Failed');
      }
    } catch (error) {
      console.error('Error:', error);
      notify.error('An error occurred while deleting user', 'Network Error');
    }
  }
}

// Delete content function
async function deleteContent(contentId) {
  const confirmed = await modal.confirm(
    'Are you sure you want to delete this content? This action cannot be undone.',
    'Delete Content',
    { type: 'danger', confirmText: 'Delete Content' }
  );

  if (confirmed) {
    try {
      const response = await fetch(`/contents/${contentId}/delete`, {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      const data = await response.json();

      if (data.success) {
        notify.success('Content deleted successfully');
        setTimeout(() => location.reload(), 1000);
      } else {
        notify.error(data.error || 'An error occurred', 'Delete Failed');
      }
    } catch (error) {
      console.error('Error:', error);
      notify.error('An error occurred while deleting content', 'Network Error');
    }
  }
}

// Copy content to clipboard
function copyToClipboard(content) {
  navigator.clipboard.writeText(content).then(
    function () {
      notify.success('Content copied to clipboard successfully!', 'Copied');
    },
    function (err) {
      console.error('Could not copy text: ', err);
      notify.error('Failed to copy content to clipboard', 'Copy Failed');
    }
  );
}

// Event delegation for data-action buttons
document.addEventListener('click', function (event) {
  const target = event.target;
  const action = target.getAttribute('data-action');

  if (!action) return;

  switch (action) {
    case 'toggle-user':
      const userId = target.getAttribute('data-user-id');
      if (userId) toggleUserStatus(userId);
      break;

    case 'delete-user':
      const deleteUserId = target.getAttribute('data-user-id');
      if (deleteUserId) deleteUser(deleteUserId);
      break;

    case 'reset-attempts':
      const resetUserId = target.getAttribute('data-user-id');
      if (resetUserId) resetUserAttempts(resetUserId);
      break;

    case 'delete-content':
      const contentId = target.getAttribute('data-content-id');
      if (contentId) deleteContent(contentId);
      break;

    case 'copy-content':
      const content = target.getAttribute('data-content');
      if (content) copyToClipboard(content);
      break;
  }
});

// Test toast function
function testToast() {
  if (window.notify) {
    window.notify.success('This is a test toast message!', '🧪 Test Successful');
    console.log('Test toast triggered');
  } else {
    console.error('Notify system not available');
    alert('Notify system not available');
  }
}

// Debug flash messages function
function debugFlashMessages() {
  console.log('=== Flash Messages Debug ===');
  const flashData = document.querySelector('[data-flash-messages]');
  console.log('Flash data element:', flashData);
  
  if (flashData) {
    const rawData = flashData.getAttribute('data-flash-messages');
    console.log('Raw flash data:', rawData);
    
    try {
      const parsed = JSON.parse(rawData);
      console.log('Parsed flash data:', parsed);
      console.log('Type:', typeof parsed);
      console.log('Length:', parsed.length);
      
      parsed.forEach((item, index) => {
        console.log(`Message ${index}:`, item);
      });
    } catch (e) {
      console.error('Parse error:', e);
    }
  } else {
    console.log('No flash data element found');
    
    // Check if there are any elements with flash-related attributes
    const allElements = document.querySelectorAll('*');
    const flashElements = Array.from(allElements).filter(el => 
      el.hasAttribute('data-flash-messages') || 
      el.textContent.includes('flash') ||
      el.className.includes('flash')
    );
    console.log('Elements with flash-related content:', flashElements);
  }
  console.log('=== End Debug ===');
}

// Show login success toast
function showLoginSuccess(username) {
  if (window.notify) {
    window.notify.success(`Welcome back, ${username}!`, '🎉 Login Successful');
  }
}

// Show logout success toast
function showLogoutSuccess(username) {
  if (window.notify) {
    window.notify.success(`Goodbye ${username}! You have been logged out successfully.`, '👋 Logout Successful');
  }
}

// Show user creation success toast
function showUserCreated(username) {
  if (window.notify) {
    window.notify.success(`User ${username} created successfully`, '✅ User Created');
  }
}

// Show login error toast
function showLoginError(message) {
  if (window.notify) {
    window.notify.error(message, '🔐 Login Failed');
  }
}

// Show user creation error toast
function showUserCreationError(message) {
  if (window.notify) {
    window.notify.error(message, '👤 User Creation Failed');
  }
}

// Initialize page-specific functionality
document.addEventListener('DOMContentLoaded', function () {
  // Add any page-specific initialization here
  console.log('Content Manager initialized');
  
  // Check URL parameters for toast messages
  const urlParams = new URLSearchParams(window.location.search);
  let shouldCleanUrl = false;
  
  if (urlParams.has('login_success')) {
    const username = urlParams.get('username') || 'User';
    showLoginSuccess(username);
    shouldCleanUrl = true;
  }
  
  if (urlParams.has('logout_success')) {
    const username = urlParams.get('username') || 'User';
    showLogoutSuccess(username);
    shouldCleanUrl = true;
  }
  
  if (urlParams.has('user_created')) {
    const username = urlParams.get('username') || 'User';
    showUserCreated(username);
    shouldCleanUrl = true;
  }
  
  if (urlParams.has('login_error')) {
    const message = urlParams.get('message') || 'Invalid username or password';
    showLoginError(message);
    shouldCleanUrl = true;
  }
  
  if (urlParams.has('user_error')) {
    const message = urlParams.get('message') || 'User creation failed';
    showUserCreationError(message);
    shouldCleanUrl = true;
  }
  
  // Clean URL parameters after showing toast to prevent re-showing on refresh
  if (shouldCleanUrl) {
    // Remove toast-related parameters from URL
    urlParams.delete('login_success');
    urlParams.delete('logout_success');
    urlParams.delete('user_created');
    urlParams.delete('login_error');
    urlParams.delete('user_error');
    urlParams.delete('username');
    urlParams.delete('message');
    
    // Update URL without page reload
    const newUrl = window.location.pathname + (urlParams.toString() ? '?' + urlParams.toString() : '');
    window.history.replaceState({}, '', newUrl);
  }
});
