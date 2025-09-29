// Content Manager - Dashboard JavaScript

// Dashboard specific functionality
document.addEventListener('DOMContentLoaded', function() {
  const generateBtn = document.getElementById('generate-btn');
  const generateSpinner = document.getElementById('generate-spinner');
  const generateBtnText = document.getElementById('generate-btn-text');
  const contentArea = document.getElementById('content-area');
  const saveContentBtn = document.getElementById('save-content-btn');
  const wordCountSlider = document.getElementById('word-count');
  const wordCountValue = document.getElementById('word-count-value');

  if (!generateBtn || !contentArea || !saveContentBtn) {
    return; // Not on dashboard page
  }

  // Word count slider functionality
  if (wordCountSlider && wordCountValue) {
    function updateSlider() {
      const value = wordCountSlider.value;
      const min = wordCountSlider.min;
      const max = wordCountSlider.max;
      const percentage = ((value - min) / (max - min)) * 100;
      
      // Update the displayed value
      wordCountValue.textContent = value;
      
      // Update the slider track color with CSS custom property
      wordCountSlider.style.setProperty('--value', percentage + '%');
      
      // Also update the background directly for better browser support
      wordCountSlider.style.background = `linear-gradient(to right, #3b82f6 0%, #3b82f6 ${percentage}%, #e5e7eb ${percentage}%, #e5e7eb 100%)`;
    }
    
    wordCountSlider.addEventListener('input', updateSlider);
    wordCountSlider.addEventListener('change', updateSlider);
    
    // Initialize the slider
    updateSlider();
  }

  // Writing style dropdown functionality
  const writingStyleDropdown = document.getElementById('writing-style-dropdown');
  const writingStyleOptions = document.getElementById('writing-style-options');
  const writingStyleDisplay = document.getElementById('writing-style-display');
  const writingStyleCheckboxes = document.querySelectorAll('.writing-style-checkbox');

  if (writingStyleDropdown && writingStyleOptions) {
    // Toggle dropdown
    writingStyleDropdown.addEventListener('click', function(e) {
      e.stopPropagation();
      writingStyleOptions.classList.toggle('hidden');
    });

    // Close dropdown when clicking outside
    document.addEventListener('click', function() {
      writingStyleOptions.classList.add('hidden');
    });

    // Prevent dropdown from closing when clicking inside options
    writingStyleOptions.addEventListener('click', function(e) {
      e.stopPropagation();
    });

    // Handle checkbox changes
    writingStyleCheckboxes.forEach(checkbox => {
      checkbox.addEventListener('change', function() {
        // Update display text and manage disabled state
        updateWritingStyleDisplay();
        updateCheckboxStates();
      });
    });

    // Function to update display text
    function updateWritingStyleDisplay() {
      const checkedBoxes = document.querySelectorAll('.writing-style-checkbox:checked');
      if (checkedBoxes.length === 0) {
        writingStyleDisplay.textContent = 'ရွေးချယ်ပါ...';
        writingStyleDisplay.className = 'text-gray-500';
      } else {
        const selectedTexts = Array.from(checkedBoxes).map(checkbox => {
          return checkbox.parentElement.querySelector('span').textContent;
        });
        writingStyleDisplay.textContent = selectedTexts.join(', ');
        writingStyleDisplay.className = 'text-gray-900';
      }
    }

    // Function to manage checkbox disabled states
    function updateCheckboxStates() {
      const checkedBoxes = document.querySelectorAll('.writing-style-checkbox:checked');
      const isMaxSelected = checkedBoxes.length >= 3;

      writingStyleCheckboxes.forEach(checkbox => {
        const label = checkbox.parentElement;
        
        if (!checkbox.checked && isMaxSelected) {
          // Disable unchecked checkboxes when 3 are selected
          checkbox.disabled = true;
          label.classList.add('opacity-50', 'cursor-not-allowed');
          label.classList.remove('cursor-pointer', 'hover:bg-gray-50');
        } else {
          // Enable all checkboxes when less than 3 are selected
          checkbox.disabled = false;
          label.classList.remove('opacity-50', 'cursor-not-allowed');
          label.classList.add('cursor-pointer');
          if (!checkbox.checked) {
            label.classList.add('hover:bg-gray-50');
          }
        }
      });
    }
  }

  // Generate content functionality
  generateBtn.addEventListener('click', async function() {
    const prompt = document.getElementById('prompt').value;
    const purpose = document.getElementById('purpose').value;
    
    // Get selected writing styles from checkboxes
    const selectedStyles = [];
    document.querySelectorAll('.writing-style-checkbox:checked').forEach(checkbox => {
      selectedStyles.push(checkbox.value);
    });
    const writingStyle = selectedStyles.join(', ');
    
    const audience = document.getElementById('audience').value;
    const keywords = document.getElementById('keywords').value;
    const hashtags = document.getElementById('hashtags').value;
    const cta = document.getElementById('cta').value;
    const negativeConstraints = document.getElementById('negative-constraints').value;

    if (!prompt.trim()) {
      notify.warning('Please enter a prompt to generate content', 'Missing Prompt');
      return;
    }

    try {
      // Set loading state
      generateBtn.disabled = true;
      generateSpinner.classList.remove('hidden');
      generateBtnText.textContent = 'Generating...';
      contentArea.value = '';
      saveContentBtn.disabled = true;

      const formData = new FormData();
      formData.append('prompt', prompt);
      formData.append('purpose', purpose);
      formData.append('writingStyle', writingStyle);
      formData.append('audience', audience);
      formData.append('wordCount', document.getElementById('word-count').value);
      formData.append('keywords', keywords);
      formData.append('hashtags', hashtags);
      formData.append('cta', cta);
      formData.append('negativeConstraints', negativeConstraints);
      formData.append('copywritingModel', document.getElementById('copywriting-model').value);
      formData.append('language', document.getElementById('language').value);

      const imageFile = document.getElementById('image-upload').files[0];
      if (imageFile) {
        // Check file size (7MB limit)
        const maxSize = 7 * 1024 * 1024; // 7MB
        if (imageFile.size > maxSize) {
          notify.error('Image file is too large. Please use an image smaller than 7MB.', 'File Too Large');
          return;
        }
        
        // Check file type
        const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp'];
        if (!allowedTypes.includes(imageFile.type)) {
          notify.error('Please upload a valid image file (JPG, PNG, or WebP).', 'Invalid File Type');
          return;
        }
        
        formData.append('image', imageFile);
      }

      const response = await fetch('/generate-content', {
        method: 'POST',
        body: formData
      });

      const data = await response.json();
      
      if (data.error) {
        notify.error(data.error, 'Generation Failed');
      } else {
        contentArea.value = data.content;
        saveContentBtn.disabled = false;
        notify.success('Content generated successfully!', 'Success');
      }
    } catch (error) {
      console.error('Error:', error);
      notify.error('An error occurred while generating content', 'Network Error');
    } finally {
      // Reset loading state
      generateBtn.disabled = false;
      generateSpinner.classList.add('hidden');
      generateBtnText.textContent = 'Generate Content';
    }
  });

  // Save content functionality
  saveContentBtn.addEventListener('click', async function() {
    const content = contentArea.value;
    const promptText = document.getElementById('prompt').value;
    
    if (!content.trim()) {
      notify.warning('No content to save', 'Missing Content');
      return;
    }

    // Create a modal for saving content
    const title = await modal.prompt(
      'Enter a title for this content:',
      'Save Content',
      promptText.substring(0, 50),
      'Content title...'
    );
    
    if (title) {
      try {
        saveContentBtn.disabled = true;
        saveContentBtn.textContent = 'Saving...';
        
        // Get selected writing styles for saving
        const selectedStylesForSave = [];
        document.querySelectorAll('.writing-style-checkbox:checked').forEach(checkbox => {
          selectedStylesForSave.push(checkbox.value);
        });
        
        const formData = new FormData();
        formData.append('title', title);
        formData.append('content', content);
        formData.append('purpose', document.getElementById('purpose').value);
        formData.append('writing_style', selectedStylesForSave.join(', '));
        formData.append('audience', document.getElementById('audience').value);
        formData.append('keywords', document.getElementById('keywords').value);
        formData.append('hashtags', document.getElementById('hashtags').value);
        formData.append('cta', document.getElementById('cta').value);
        formData.append('negative_constraints', document.getElementById('negative-constraints').value);
        
        const response = await fetch('/contents/save', {
          method: 'POST',
          body: formData
        });
        
        const data = await response.json();
        
        if (data.success) {
          notify.success('Content saved successfully!', 'Saved');
          
          // Update total content count
          updateTotalContentCount();
          
          // Add new content to recent content list
          addToRecentContentList(data.content);
          
          // Clear the content area and reset form
          contentArea.value = '';
          document.getElementById('prompt').value = '';
          saveContentBtn.disabled = true;
          saveContentBtn.textContent = 'Save Content';
        } else {
          notify.error(data.error || 'An error occurred', 'Save Failed');
        }
      } catch (error) {
        console.error('Error:', error);
        notify.error('An error occurred while saving content', 'Network Error');
      } finally {
        saveContentBtn.disabled = false;
        saveContentBtn.textContent = 'Save Content';
      }
    }
  });
});

// Function to update total content count
function updateTotalContentCount() {
  // Look for the total count in the gradient box
  const totalContentElement = document.querySelector('.bg-gradient-to-r.from-blue-600 p');
  if (totalContentElement) {
    const currentCount = parseInt(totalContentElement.textContent) || 0;
    totalContentElement.textContent = currentCount + 1;
  }
}

// Function to add new content to recent content list
function addToRecentContentList(contentData) {
  const recentContentList = document.querySelector('.space-y-3');
  if (recentContentList && contentData) {
    // Create new content item matching the template structure
    const contentItem = document.createElement('div');
    contentItem.className = 'border-l-4 border-indigo-400 pl-4 py-2';
    contentItem.innerHTML = `
      <div class="flex flex-col sm:flex-row sm:justify-between sm:items-start space-y-2 sm:space-y-0">
        <div class="flex-1 min-w-0">
          <h3 class="font-medium text-gray-900">
            <a href="/contents/${contentData.id}" class="hover:text-indigo-600 block sm:inline">
              ${contentData.title}
            </a>
          </h3>
          <p class="text-sm text-gray-600 truncate">${contentData.content.substring(0, 100)}${contentData.content.length > 100 ? '...' : ''}</p>
          <p class="text-xs text-gray-500">Just now</p>
        </div>
        <span class="inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-gray-100 text-gray-800 self-start sm:ml-4">
          ${contentData.purpose || 'General'}
        </span>
      </div>
    `;
    
    // Add to the top of the list
    recentContentList.insertBefore(contentItem, recentContentList.firstChild);
    
    // Remove the last item if there are more than 3 items
    const contentItems = recentContentList.querySelectorAll('.border-l-4');
    if (contentItems.length > 3) {
      recentContentList.removeChild(contentItems[contentItems.length - 1]);
    }
    
    // Hide "No content created yet" message if it exists
    const noContentMessage = document.querySelector('.text-gray-500.text-center.py-8');
    if (noContentMessage) {
      noContentMessage.style.display = 'none';
    }
  }
}
