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
  // Find the status badge in the Status column (3rd td element, index 2)
  const statusCell = userRow.querySelectorAll('td')[2]; // Status is the 3rd column (index 2)
  const statusBadge = statusCell.querySelector('.inline-flex');

  // Save original button HTML for restoration if needed
  const originalButtonHTML = button.innerHTML;
  const originalButtonClass = button.className;
  const originalButtonTitle = button.title;

  // Get the action from the button title
  const action = button.title.toLowerCase().includes('deactivate') ? 'deactivate' : 'activate';
  const actionTitle = action.charAt(0).toUpperCase() + action.slice(1);

  const confirmed = await modal.confirm(
    `Are you sure you want to ${action} this user?`,
    `${actionTitle} User`,
    { confirmText: actionTitle }
  );

  if (confirmed) {
    // Show loading state
    button.disabled = true;
    button.innerHTML = '<span style="font-size: 12px;">Processing...</span>';

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

        // Update the status badge and button icon without reloading
        if (data.new_status) {
          // User is now active - show deactivate icon (shield-minus)
          statusBadge.className =
            'inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-green-600/20 text-green-300';
          statusBadge.textContent = 'Active';
          button.className = 'text-yellow-600 hover:text-yellow-700 p-1';
          button.title = 'Deactivate user';
          button.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>
            <path d="M9 12h6"/>
          </svg>`;
        } else {
          // User is now inactive - show activate icon (shield-plus)
          statusBadge.className =
            'inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-red-600/20 text-red-300';
          statusBadge.textContent = 'Inactive';
          button.className = 'text-green-600 hover:text-green-700 p-1';
          button.title = 'Activate user';
          button.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-shield-plus">
            <path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>
            <path d="M9 12h6"/>
            <path d="M12 9v6"/>
          </svg>`;
        }
      } else {
        notify.error(data.error || 'An error occurred', 'Update Failed');
        // Restore original button state
        button.innerHTML = originalButtonHTML;
        button.className = originalButtonClass;
        button.title = originalButtonTitle;
      }
    } catch (error) {
      console.error('Error:', error);
      notify.error('An error occurred while updating user status', 'Network Error');
      // Restore original button state
      button.innerHTML = originalButtonHTML;
      button.className = originalButtonClass;
      button.title = originalButtonTitle;
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
  // Check if modal is available
  if (!window.modal) {
    alert('Modal system not loaded. Please refresh the page.');
    return;
  }

  const message = window.getTranslation
    ? window.getTranslation(
        'Are you sure you want to delete this content? This action cannot be undone.'
      )
    : 'Are you sure you want to delete this content? This action cannot be undone.';

  const title = window.getTranslation ? window.getTranslation('Delete Content') : 'Delete Content';

  const confirmText = window.getTranslation
    ? window.getTranslation('Delete Content')
    : 'Delete Content';

  const confirmed = await modal.confirm(message, title, {
    type: 'danger',
    confirmText: confirmText,
  });

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
        const successMsg = window.getTranslation
          ? window.getTranslation('Content deleted successfully!')
          : 'Content deleted successfully!';
        notify.success(successMsg);
        setTimeout(() => location.reload(), 1000);
      } else {
        const errorMsg = window.getTranslation
          ? window.getTranslation('Error generating content. Please try again.')
          : 'An error occurred';
        notify.error(data.error || errorMsg, 'Delete Failed');
      }
    } catch (error) {
      console.error('Error:', error);
      const networkErrorMsg = window.getTranslation
        ? window.getTranslation('Error generating content. Please try again.')
        : 'An error occurred while deleting content';
      notify.error(networkErrorMsg, 'Network Error');
    }
  }
}

// Copy content to clipboard
function copyToClipboard(content) {
  navigator.clipboard.writeText(content).then(
    function () {
      const successMsg = window.getTranslation
        ? window.getTranslation('Content copied to clipboard!')
        : 'Content copied to clipboard!';
      notify.success(successMsg, 'Copied');
    },
    function (err) {
      notify.error('Failed to copy content to clipboard', 'Copy Failed');
    }
  );
}

// Event delegation for data-action buttons
document.addEventListener('click', function (event) {
  const target = event.target.closest('[data-action]');
  if (!target) return;

  const action = target.getAttribute('data-action');

  switch (action) {
    case 'toggle-user':
      const userId = target.getAttribute('data-user-id');
      if (userId) toggleUserStatus(userId);
      break;

    case 'reset-attempts':
      const resetUserId = target.getAttribute('data-user-id');
      if (resetUserId) resetUserAttempts(resetUserId);
      break;

    case 'delete-user':
      const deleteUserId = target.getAttribute('data-user-id');
      if (deleteUserId) deleteUser(deleteUserId);
      break;

    case 'delete-content':
      const contentId = target.getAttribute('data-content-id');
      if (contentId) {
        deleteContent(contentId);
      }
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
  } else {
    alert('Notify system not available');
  }
}

// Show login success toast
function showLoginSuccess(username) {
  if (window.notify) {
    window.notify.success(`Welcome back, ${username}!`, '🎉 Login Successful');
  } else {
    alert('Notify system not available');
  }
}

// Show logout success toast
function showLogoutSuccess(username) {
  if (window.notify) {
    window.notify.success(
      `Goodbye ${username}! You have been logged out successfully.`,
      '👋 Logout Successful'
    );
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
    const newUrl =
      window.location.pathname + (urlParams.toString() ? '?' + urlParams.toString() : '');
    window.history.replaceState({}, '', newUrl);
  }
});
