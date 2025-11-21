// Contents Dashboard JavaScript

document.addEventListener('DOMContentLoaded', function () {
  const searchInput = document.getElementById('search-input');
  const filterSelect = document.getElementById('filter-select');
  const contentsList = document.getElementById('contents-list');
  const showingCount = document.getElementById('showing-count');
  const totalShowing = document.getElementById('total-showing');
  const FALLBACK_TIMEZONE = 'Asia/Yangon';
  let browserTimeZone = null;
  try {
    browserTimeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  } catch (error) {
    browserTimeZone = null;
  }
  const userTimeZone = browserTimeZone || FALLBACK_TIMEZONE;
  const locale = navigator.language || 'en-US';
  const dateTimeFormatOptions = {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    hour12: true,
  };

  // Initialize
  updateCounts();
  applyLocalTimezone();
  window.formatDateToUserTimezone = formatToUserTimezone;
  window.activeUserTimeZone = userTimeZone;

  // Search functionality
  if (searchInput) {
    searchInput.addEventListener('input', debounce(filterContents, 300));
  }

  function formatToUserTimezone(isoString) {
    if (!isoString) return '';
    const parsedDate = new Date(isoString);
    if (Number.isNaN(parsedDate.getTime())) {
      return '';
    }
    try {
      const formatter = new Intl.DateTimeFormat(locale, {
        ...dateTimeFormatOptions,
        timeZone: userTimeZone,
      });
      return formatter.format(parsedDate);
    } catch (error) {
      return parsedDate.toLocaleString(locale, {
        ...dateTimeFormatOptions,
        timeZone: userTimeZone,
      });
    }
  }

  function applyLocalTimezone() {
    document.querySelectorAll('.meta-date[data-date-iso]').forEach(dateEl => {
      const { dateIso } = dateEl.dataset;
      if (dateIso) {
        dateEl.textContent = formatToUserTimezone(dateIso);
      }
    });
    document.querySelectorAll('[data-timezone-display]').forEach(tzEl => {
      tzEl.textContent = userTimeZone;
    });
  }

  // Filter functionality
  if (filterSelect) {
    filterSelect.addEventListener('change', filterContents);
  }

  // Toggle publish status
  document.querySelectorAll('.publish-toggle').forEach(toggle => {
    toggle.addEventListener('change', async function () {
      const contentId = this.dataset.contentId;
      const isPublished = this.checked;

      try {
        const response = await fetch(`/api/contents/${contentId}/toggle-publish`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ published: isPublished }),
        });

        const data = await response.json();

        if (data.success) {
          // Update the status badge
          const contentItem = this.closest('.content-item');
          const statusBadge = contentItem.querySelector('.status-badge');

          if (isPublished) {
            statusBadge.classList.remove('status-draft');
            statusBadge.classList.add('status-published');
            statusBadge.innerHTML = '<span data-translate="Posted">Posted</span>';
            contentItem.dataset.published = 'true';
          } else {
            statusBadge.classList.remove('status-published');
            statusBadge.classList.add('status-draft');
            statusBadge.innerHTML = '<span data-translate="Not Posted">Not Posted</span>';
            contentItem.dataset.published = 'false';
          }

          // Update stats
          updateStats();

          // Show success notification
          if (window.notify) {
            const message = isPublished
              ? 'Content published successfully!'
              : 'Content moved to drafts!';
            notify.success(message, 'Success');
          }
        } else {
          // Revert toggle on error
          this.checked = !isPublished;
          if (window.notify) {
            notify.error(data.error || 'Failed to update content status', 'Error');
          }
        }
      } catch (error) {
        console.error('Error toggling publish status:', error);
        // Revert toggle on error
        this.checked = !isPublished;
        if (window.notify) {
          notify.error('An error occurred while updating content status', 'Error');
        }
      }
    });
  });

  // View content
  document.querySelectorAll('.action-view').forEach(btn => {
    btn.addEventListener('click', function () {
      const contentId = this.dataset.contentId;
      openViewModal(contentId);
    });
  });

  // Edit content
  document.querySelectorAll('.action-edit').forEach(btn => {
    btn.addEventListener('click', function () {
      const contentId = this.dataset.contentId;
      openEditModal(contentId);
    });
  });

  // Delete content - Use event delegation for dynamically loaded content
  if (contentsList) {
    contentsList.addEventListener('click', async function (e) {
      const deleteBtn = e.target.closest('.action-delete');
      if (!deleteBtn) return;

      const contentId = deleteBtn.dataset.contentId;
      const contentItem = deleteBtn.closest('.content-item');
      const contentTitle = contentItem.querySelector('.content-title').textContent;

      // Show confirmation modal
      const confirmed = await showDeleteConfirmation(contentTitle);

      if (confirmed) {
        try {
          const response = await fetch(`/contents/${contentId}/delete`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
          });

          const data = await response.json();

          if (data.success) {
            // Remove the content item from DOM
            contentItem.style.opacity = '0';
            contentItem.style.transform = 'translateX(-20px)';

            setTimeout(() => {
              contentItem.remove();
              updateStats();
              updateCounts();

              // Show empty state if no contents left
              const remainingItems = document.querySelectorAll('.content-item');
              if (remainingItems.length === 0) {
                showEmptyState();
              }
            }, 300);

            if (window.notify) {
              notify.success('Content deleted successfully!', 'Success');
            }
          } else {
            if (window.notify) {
              notify.error(data.error || 'Failed to delete content', 'Error');
            }
          }
        } catch (error) {
          console.error('Error deleting content:', error);
          if (window.notify) {
            notify.error('An error occurred while deleting content', 'Error');
          }
        }
      }
    });
  }

  // Filter contents based on search and filter
  function filterContents() {
    const searchTerm = searchInput.value.toLowerCase().trim();
    const filterValue = filterSelect.value;

    const contentItems = document.querySelectorAll('.content-item');
    let visibleCount = 0;

    contentItems.forEach(item => {
      const title = item.querySelector('.content-title').textContent.toLowerCase();
      const preview = item.querySelector('.content-preview').textContent.toLowerCase();
      const isPublished = item.dataset.published === 'true';

      let matchesSearch = true;
      let matchesFilter = true;

      // Check search
      if (searchTerm) {
        matchesSearch = title.includes(searchTerm) || preview.includes(searchTerm);
      }

      // Check filter
      if (filterValue === 'published') {
        matchesFilter = isPublished;
      } else if (filterValue === 'drafts') {
        matchesFilter = !isPublished;
      }

      // Show/hide item
      if (matchesSearch && matchesFilter) {
        item.style.display = 'block';
        visibleCount++;
      } else {
        item.style.display = 'none';
      }
    });

    // Update showing count
    if (showingCount) {
      showingCount.textContent = visibleCount;
    }

    // Show empty state if no results
    if (visibleCount === 0) {
      showNoResultsState();
    } else {
      hideNoResultsState();
    }
  }

  // Update stats (published/drafts counts)
  function updateStats() {
    const contentItems = document.querySelectorAll('.content-item');
    let publishedCount = 0;
    let draftsCount = 0;

    contentItems.forEach(item => {
      if (item.dataset.published === 'true') {
        publishedCount++;
      } else {
        draftsCount++;
      }
    });

    const publishedCountEl = document.getElementById('published-count');
    const draftsCountEl = document.getElementById('drafts-count');

    if (publishedCountEl) {
      publishedCountEl.textContent = publishedCount;
    }

    if (draftsCountEl) {
      draftsCountEl.textContent = draftsCount;
    }
  }

  // Update counts
  function updateCounts() {
    const contentItems = document.querySelectorAll('.content-item');
    const visibleItems = Array.from(contentItems).filter(item => item.style.display !== 'none');

    if (showingCount) {
      showingCount.textContent = visibleItems.length;
    }

    if (totalShowing) {
      totalShowing.textContent = contentItems.length;
    }
  }

  // Show delete confirmation
  async function showDeleteConfirmation(contentTitle) {
    if (window.modal && window.modal.confirm) {
      const message = window.getTranslation
        ? window.getTranslation('Are you sure you want to delete this content?')
        : 'Are you sure you want to delete this content?';

      const title = window.getTranslation
        ? window.getTranslation('Delete Content')
        : 'Delete Content';

      const confirmText = window.getTranslation ? window.getTranslation('Delete') : 'Delete';

      return await window.modal.confirm(`${message}\n\n"${contentTitle}"`, title, {
        type: 'danger',
        confirmText: confirmText,
      });
    } else {
      // Fallback to native confirm
      return confirm(`Are you sure you want to delete "${contentTitle}"?`);
    }
  }

  // Show empty state
  function showEmptyState() {
    const contentsList = document.getElementById('contents-list');
    if (contentsList) {
      contentsList.innerHTML = `
        <div class="empty-state">
          <svg class="empty-state-icon" xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/>
            <polyline points="14 2 14 8 20 8"/>
          </svg>
          <p class="empty-state-text" data-translate="No contents found">No contents found</p>
        </div>
      `;
    }
  }

  // Show no results state
  function showNoResultsState() {
    const existingNoResults = document.querySelector('.no-results-state');
    if (!existingNoResults) {
      const contentsList = document.getElementById('contents-list');
      const noResultsDiv = document.createElement('div');
      noResultsDiv.className = 'empty-state no-results-state';
      noResultsDiv.innerHTML = `
        <svg class="empty-state-icon" xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="11" cy="11" r="8"/>
          <path d="m21 21-4.3-4.3"/>
        </svg>
        <p class="empty-state-text" data-translate="No contents match your search">No contents match your search</p>
      `;
      contentsList.appendChild(noResultsDiv);
    }
  }

  // Hide no results state
  function hideNoResultsState() {
    const noResultsState = document.querySelector('.no-results-state');
    if (noResultsState) {
      noResultsState.remove();
    }
  }

  // Debounce function
  function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
      const later = () => {
        clearTimeout(timeout);
        func(...args);
      };
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
    };
  }
});

// Modal Functions
function openViewModal(contentId) {
  const contentItem = document.querySelector(`.content-item[data-content-id="${contentId}"]`);
  if (!contentItem) {
    console.error('Content item not found');
    return;
  }

  const title = contentItem.querySelector('.content-title').textContent;
  const content = contentItem.querySelector('.content-preview').textContent;
  const statusBadge = contentItem.querySelector('.status-badge');
  const isPublished = contentItem.dataset.published === 'true';
  const created = contentItem.querySelector('.meta-item:first-child').textContent.split(': ')[1];
  const updated = contentItem.querySelector('.meta-item:last-child').textContent.split(': ')[1];

  // Helper function to format date
  function formatDate(isoString) {
    if (window.formatDateToUserTimezone) {
      return window.formatDateToUserTimezone(isoString);
    }
    if (!isoString) return '';
    const date = new Date(isoString);
    const options = {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: 'numeric',
      minute: '2-digit',
      hour12: true,
    };
    return date.toLocaleString('en-US', options);
  }

  // Fetch full content
  fetch(`/api/contents/${contentId}`)
    .then(response => response.json())
    .then(data => {
      if (data.success) {
        document.getElementById('view-modal-title').textContent = data.content.title;
        document.getElementById('view-modal-content').textContent = data.content.content;
        document.getElementById('view-modal-created').textContent = formatDate(
          data.content.created_at
        );
        document.getElementById('view-modal-updated').textContent = formatDate(
          data.content.updated_at
        );
        document.querySelectorAll('#view-modal [data-timezone-display]').forEach(tzEl => {
          tzEl.textContent = window.activeUserTimeZone || FALLBACK_TIMEZONE;
        });

        const viewStatusBadge = document.getElementById('view-modal-status');
        if (data.content.published) {
          viewStatusBadge.className = 'status-badge status-published';
          viewStatusBadge.innerHTML = `
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/>
              <circle cx="12" cy="12" r="3"/>
            </svg>
            <span data-translate="Posted">Posted</span>
          `;
        } else {
          viewStatusBadge.className = 'status-badge status-draft';
          viewStatusBadge.innerHTML = `
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M10.733 5.076a10.744 10.744 0 0 1 11.205 6.575 1 1 0 0 1 0 .696 10.747 10.747 0 0 1-1.444 2.49"/>
              <path d="M14.084 14.158a3 3 0 0 1-4.242-4.242"/>
              <path d="M17.479 17.499a10.75 10.75 0 0 1-15.417-5.151 1 1 0 0 1 0-.696 10.75 10.75 0 0 1 4.446-5.143"/>
              <path d="m2 2 20 20"/>
            </svg>
            <span data-translate="Not Posted">Not Posted</span>
          `;
        }

        const modal = document.getElementById('view-modal');
        modal.style.display = 'block';
        document.body.style.overflow = 'hidden';
      }
    })
    .catch(error => {
      console.error('Error fetching content:', error);
      if (window.notify) {
        notify.error('Failed to load content', 'Error');
      }
    });
}

function closeViewModal() {
  document.getElementById('view-modal').style.display = 'none';
  document.body.style.overflow = '';
}

function copyContent() {
  const content = document.getElementById('view-modal-content').textContent;
  const copyBtn = event.target.closest('.btn-primary');
  const copyBtnText = copyBtn.querySelector('span');
  const originalText = copyBtnText.textContent;

  navigator.clipboard
    .writeText(content)
    .then(() => {
      // Update button text to "Copied!"
      const copiedText = window.getTranslation ? window.getTranslation('Copied!') : 'Copied!';
      copyBtnText.textContent = copiedText;
      copyBtnText.setAttribute('data-translate', 'Copied!');

      // Show success notification
      if (window.notify) {
        const successMsg = window.getTranslation
          ? window.getTranslation('Content copied to clipboard!')
          : 'Content copied to clipboard!';
        notify.success(successMsg, 'Success');
      }

      // Reset button text after 2 seconds
      setTimeout(() => {
        copyBtnText.textContent = window.getTranslation ? window.getTranslation('Copy') : 'Copy';
        copyBtnText.setAttribute('data-translate', 'Copy');
      }, 2000);
    })
    .catch(err => {
      console.error('Failed to copy:', err);
      if (window.notify) {
        const errorMsg = window.getTranslation
          ? window.getTranslation('Failed to copy content')
          : 'Failed to copy content';
        notify.error(errorMsg, 'Error');
      }
    });
}

function openEditModal(contentId) {
  fetch(`/api/contents/${contentId}`)
    .then(response => response.json())
    .then(data => {
      if (data.success) {
        document.getElementById('edit-content-id').value = contentId;
        document.getElementById('edit-title').value = data.content.title;
        document.getElementById('edit-content').value = data.content.content;

        const editModal = document.getElementById('edit-modal');
        editModal.style.display = 'block';
        document.body.style.overflow = 'hidden';
      }
    })
    .catch(error => {
      console.error('Error fetching content:', error);
      if (window.notify) {
        notify.error('Failed to load content', 'Error');
      }
    });
}

function closeEditModal() {
  document.getElementById('edit-modal').style.display = 'none';
  document.body.style.overflow = '';
}

function updateContent() {
  const contentId = document.getElementById('edit-content-id').value;
  const title = document.getElementById('edit-title').value;
  const content = document.getElementById('edit-content').value;

  if (!title || !content) {
    if (window.notify) {
      notify.error('Please fill in all fields', 'Error');
    }
    return;
  }

  // Get button element first
  let updateButton = document.getElementById('updateButton');

  if (!updateButton) {
    return;
  }

  // Get spinner and text from within the button
  let updateSpinner = updateButton.querySelector('svg');
  let updateButtonText = updateButton.querySelector('span');

  // If elements don't exist (old cached HTML), create them dynamically
  if (!updateSpinner) {
    const originalText = updateButton.textContent;
    updateButton.innerHTML = '';

    // Create spinner SVG (same as login)
    updateSpinner = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    updateSpinner.setAttribute('id', 'updateSpinner');
    updateSpinner.setAttribute('class', 'animate-spin');
    updateSpinner.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
    updateSpinner.setAttribute('fill', 'none');
    updateSpinner.setAttribute('viewBox', '0 0 24 24');
    updateSpinner.style.display = 'none';
    updateSpinner.style.width = '20px';
    updateSpinner.style.height = '20px';
    updateSpinner.style.marginRight = '8px';

    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('cx', '12');
    circle.setAttribute('cy', '12');
    circle.setAttribute('r', '10');
    circle.setAttribute('stroke', 'white');
    circle.setAttribute('stroke-width', '4');
    circle.style.opacity = '0.25';

    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('fill', 'white');
    path.setAttribute(
      'd',
      'M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z'
    );
    path.style.opacity = '0.75';

    updateSpinner.appendChild(circle);
    updateSpinner.appendChild(path);
    updateButton.appendChild(updateSpinner);

    // Create text span
    updateButtonText = document.createElement('span');
    updateButtonText.id = 'updateButtonText';
    updateButtonText.textContent = originalText.trim();
    updateButton.appendChild(updateButtonText);
  }

  // Also try by ID as backup
  if (!updateSpinner) {
    updateSpinner = document.getElementById('updateSpinner');
  }
  if (!updateButtonText) {
    updateButtonText = document.getElementById('updateButtonText');
  }

  if (!updateButton || !updateSpinner || !updateButtonText) {
    // Continue with update anyway
  } else {
    // Disable button and show loading state
    updateButton.disabled = true;
    updateButton.style.opacity = '0.7';
    updateButton.style.cursor = 'not-allowed';

    // Show spinner
    updateSpinner.style.display = 'inline-block';

    // Ensure white text color
    updateButtonText.style.color = 'white';

    // Change text to "Updating..." with proper translation
    updateButtonText.setAttribute('data-translate', 'Updating...');
    const currentLang = localStorage.getItem('language') || 'my';
    if (window.translations && window.translations['Updating...']) {
      updateButtonText.textContent = window.translations['Updating...'][currentLang];
    } else {
      updateButtonText.textContent = currentLang === 'my' ? 'ပြင်ဆင်နေသည်...' : 'Updating...';
    }
  }

  fetch(`/api/contents/${contentId}/update`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ title, content }),
  })
    .then(response => response.json())
    .then(data => {
      if (data.success) {
        // Update the content item in the list
        const contentItem = document.querySelector(`.content-item[data-content-id="${contentId}"]`);
        if (contentItem) {
          contentItem.querySelector('.content-title').textContent = title;
          contentItem.querySelector('.content-preview').textContent =
            content.substring(0, 150) + (content.length > 150 ? '...' : '');
        }

        // Reset button state BEFORE closing modal
        if (updateButton && updateSpinner && updateButtonText) {
          updateButton.disabled = false;
          updateButton.style.opacity = '1';
          updateButton.style.cursor = 'pointer';
          updateSpinner.style.display = 'none';
          updateButtonText.setAttribute('data-translate', 'Update');
          const currentLang = localStorage.getItem('language') || 'my';
          if (window.translations && window.translations['Update']) {
            updateButtonText.textContent = window.translations['Update'][currentLang];
          } else {
            updateButtonText.textContent = currentLang === 'my' ? 'ပြင်ဆင်မည်' : 'Update';
          }
        }

        closeEditModal();

        if (window.notify) {
          notify.success('Content updated successfully!', 'Success');
        }

        // Reload page to reflect changes
        setTimeout(() => {
          location.reload();
        }, 1000);
      } else {
        // Reset button state on error
        if (updateButton && updateSpinner && updateButtonText) {
          updateButton.disabled = false;
          updateButton.style.opacity = '1';
          updateButton.style.cursor = 'pointer';
          updateSpinner.style.display = 'none';
          updateButtonText.setAttribute('data-translate', 'Update');
          const currentLang = localStorage.getItem('language') || 'my';
          if (window.translations && window.translations['Update']) {
            updateButtonText.textContent = window.translations['Update'][currentLang];
          } else {
            updateButtonText.textContent = currentLang === 'my' ? 'ပြင်ဆင်မည်' : 'Update';
          }
        }

        if (window.notify) {
          notify.error(data.error || 'Failed to update content', 'Error');
        }
      }
    })
    .catch(error => {
      console.error('Error updating content:', error);

      // Reset button state on error
      if (updateButton && updateSpinner && updateButtonText) {
        updateButton.disabled = false;
        updateButton.style.opacity = '1';
        updateButton.style.cursor = 'pointer';
        updateSpinner.style.display = 'none';
        updateButtonText.setAttribute('data-translate', 'Update');
        const currentLang = localStorage.getItem('language') || 'my';
        if (window.translations && window.translations['Update']) {
          updateButtonText.textContent = window.translations['Update'][currentLang];
        } else {
          updateButtonText.textContent = currentLang === 'my' ? 'ပြင်ဆင်မည်' : 'Update';
        }
      }

      if (window.notify) {
        notify.error('An error occurred while updating content', 'Error');
      }
    });
}

// Close modals on outside click
document.addEventListener('click', function (e) {
  if (e.target.classList.contains('modal')) {
    closeViewModal();
    closeEditModal();
  }
});
