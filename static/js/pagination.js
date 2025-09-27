// Pagination and Search Functionality

// Search functionality
function handleSearch(event) {
  const searchTerm = event.target.value;
  const currentUrl = new URL(window.location);
  
  if (event.key === 'Enter') {
    // Immediate search on Enter
    if (searchTerm.trim()) {
      currentUrl.searchParams.set('search', searchTerm);
    } else {
      currentUrl.searchParams.delete('search');
    }
    currentUrl.searchParams.set('page', '1'); // Reset to first page
    window.location.href = currentUrl.toString();
  } else {
    // Debounced search for typing
    clearTimeout(window.searchTimeout);
    window.searchTimeout = setTimeout(() => {
      if (searchTerm.trim()) {
        currentUrl.searchParams.set('search', searchTerm);
      } else {
        currentUrl.searchParams.delete('search');
      }
      currentUrl.searchParams.set('page', '1'); // Reset to first page
      window.location.href = currentUrl.toString();
    }, 800);
  }
}

// Filter functionality
function handleFilter(event) {
  const filterValue = event.target.value;
  const currentUrl = new URL(window.location);
  
  if (filterValue) {
    currentUrl.searchParams.set('filter', filterValue);
  } else {
    currentUrl.searchParams.delete('filter');
  }
  currentUrl.searchParams.set('page', '1'); // Reset to first page
  
  window.location.href = currentUrl.toString();
}

// Enhanced table interactions
document.addEventListener('DOMContentLoaded', function() {
  // Add hover effects to table rows
  const tableRows = document.querySelectorAll('tbody tr');
  tableRows.forEach(row => {
    row.addEventListener('mouseenter', function() {
      this.classList.add('bg-blue-50');
    });
    
    row.addEventListener('mouseleave', function() {
      this.classList.remove('bg-blue-50');
    });
  });
  
  // Add loading states to pagination links
  const paginationLinks = document.querySelectorAll('.pagination-item');
  paginationLinks.forEach(link => {
    link.addEventListener('click', function(e) {
      if (!this.classList.contains('active') && !this.classList.contains('disabled')) {
        // Add loading state
        const originalText = this.textContent;
        this.innerHTML = '<div class="loading-spinner"></div>';
        this.classList.add('pagination-loading');
        
        // Reset if navigation fails
        setTimeout(() => {
          this.textContent = originalText;
          this.classList.remove('pagination-loading');
        }, 5000);
      }
    });
  });
  
  // Keyboard navigation for pagination
  document.addEventListener('keydown', function(e) {
    if (e.ctrlKey || e.metaKey) {
      const currentPage = parseInt(document.querySelector('.pagination-item.active')?.textContent || '1');
      const totalPages = document.querySelectorAll('.pagination-item:not(.prev):not(.next):not(.disabled)').length;
      
      if (e.key === 'ArrowLeft' && currentPage > 1) {
        // Go to previous page
        const prevLink = document.querySelector('.pagination-item.prev:not(.disabled)');
        if (prevLink) {
          e.preventDefault();
          prevLink.click();
        }
      } else if (e.key === 'ArrowRight' && currentPage < totalPages) {
        // Go to next page
        const nextLink = document.querySelector('.pagination-item.next:not(.disabled)');
        if (nextLink) {
          e.preventDefault();
          nextLink.click();
        }
      }
    }
  });
  
  // Auto-focus search input on page load
  const searchInput = document.getElementById('search-input');
  if (searchInput && !searchInput.value) {
    // Focus search input with a slight delay for better UX
    setTimeout(() => {
      searchInput.focus();
    }, 500);
  }
  
  // Add search input enhancements
  if (searchInput) {
    // Clear search functionality
    const clearButton = document.createElement('button');
    clearButton.innerHTML = `
      <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
      </svg>
    `;
    clearButton.className = 'absolute right-2 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600 transition-colors';
    clearButton.style.display = searchInput.value ? 'block' : 'none';
    clearButton.addEventListener('click', function() {
      searchInput.value = '';
      searchInput.focus();
      handleSearch({ target: searchInput, key: 'Enter' });
    });
    
    // Make search box relative and add clear button
    const searchBox = searchInput.closest('.search-box');
    if (searchBox) {
      searchBox.style.position = 'relative';
      searchBox.appendChild(clearButton);
      
      // Show/hide clear button based on input
      searchInput.addEventListener('input', function() {
        clearButton.style.display = this.value ? 'block' : 'none';
      });
    }
  }
  
  // Add smooth scrolling to pagination
  const paginationContainer = document.querySelector('.pagination-container');
  if (paginationContainer) {
    paginationContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
});

// Utility function to get URL parameters
function getUrlParameter(name) {
  const urlParams = new URLSearchParams(window.location.search);
  return urlParams.get(name);
}

// Update page title with current page info
function updatePageTitle() {
  const currentPage = getUrlParameter('page') || '1';
  const searchTerm = getUrlParameter('search');
  const originalTitle = document.title;
  
  let newTitle = originalTitle;
  if (currentPage !== '1') {
    newTitle += ` - Page ${currentPage}`;
  }
  if (searchTerm) {
    newTitle += ` - Search: ${searchTerm}`;
  }
  
  document.title = newTitle;
}

// Call on page load
document.addEventListener('DOMContentLoaded', updatePageTitle);

// Add visual feedback for actions
function showActionFeedback(element, message, type = 'success') {
  const feedback = document.createElement('div');
  feedback.className = `fixed top-20 right-4 px-4 py-2 rounded-lg text-white text-sm font-medium z-50 ${
    type === 'success' ? 'bg-green-500' : 'bg-red-500'
  }`;
  feedback.textContent = message;
  
  document.body.appendChild(feedback);
  
  // Animate in
  setTimeout(() => feedback.classList.add('opacity-100'), 100);
  
  // Remove after 3 seconds
  setTimeout(() => {
    feedback.classList.add('opacity-0');
    setTimeout(() => document.body.removeChild(feedback), 300);
  }, 3000);
}

// Export functions for global use
window.handleSearch = handleSearch;
window.handleFilter = handleFilter;
window.showActionFeedback = showActionFeedback;
