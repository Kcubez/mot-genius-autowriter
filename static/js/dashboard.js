// Content Manager - Dashboard JavaScript

// Loading Animation Functions
function showLoadingAnimation() {
  const overlay = document.getElementById('loading-overlay');
  if (overlay) {
    overlay.style.display = 'flex';
  }
}

function hideLoadingAnimation() {
  const overlay = document.getElementById('loading-overlay');
  if (overlay) {
    overlay.style.display = 'none';
  }
}

// Dashboard specific functionality
document.addEventListener('DOMContentLoaded', function () {
  const generateBtn = document.getElementById('generate-btn');
  const generateSpinner = document.getElementById('generate-spinner');
  const generateBtnText = document.getElementById('generate-btn-text');
  const generateMagicIcon = document.getElementById('generate-magic-icon');
  const contentArea = document.getElementById('content-area');
  const generatedContentDisplay = document.getElementById('generated-content-display');
  const saveContentBtn = document.getElementById('save-content-btn');
  const copyContentBtn = document.getElementById('copy-content-btn');
  const wordCountSelect = document.getElementById('word-count');
  const apiKeyBtn = document.getElementById('change-api-key-btn');
  const apiKeyModal = document.getElementById('api-key-modal');
  const apiKeyInput = document.getElementById('api-key-input');
  const apiKeyCancelBtn = document.getElementById('api-key-cancel-btn');
  const apiKeySubmitBtn = document.getElementById('api-key-submit-btn');
  const apiKeyCloseBtn = document.getElementById('close-api-key-modal');

  if (!generateBtn || !contentArea || !saveContentBtn) {
    return; // Not on dashboard page
  }

  // API key modal handling
  if (
    apiKeyBtn &&
    apiKeyModal &&
    apiKeyInput &&
    apiKeyCancelBtn &&
    apiKeySubmitBtn &&
    apiKeyCloseBtn
  ) {
    const toggleBodyScroll = locked => {
      document.body.style.overflow = locked ? 'hidden' : '';
    };

    const openApiKeyModal = () => {
      apiKeyInput.value = apiKeyBtn.dataset.currentKey || '';
      apiKeyModal.classList.add('active');
      apiKeyModal.setAttribute('aria-hidden', 'false');
      toggleBodyScroll(true);
      requestAnimationFrame(() => apiKeyInput.focus());
    };

    const closeApiKeyModal = () => {
      apiKeyModal.classList.remove('active');
      apiKeyModal.setAttribute('aria-hidden', 'true');
      toggleBodyScroll(false);
      apiKeyInput.value = '';
    };

    const handleEscClose = event => {
      if (event.key === 'Escape' && apiKeyModal.classList.contains('active')) {
        closeApiKeyModal();
      }
    };

    document.addEventListener('keydown', handleEscClose);
    apiKeyBtn.addEventListener('click', openApiKeyModal);
    apiKeyCancelBtn.addEventListener('click', closeApiKeyModal);
    apiKeyCloseBtn.addEventListener('click', closeApiKeyModal);
    apiKeyModal.addEventListener('click', event => {
      if (event.target === apiKeyModal) {
        closeApiKeyModal();
      }
    });

    const getChangeLabel = () => {
      if (typeof window.getTranslation === 'function') {
        return window.getTranslation('Change');
      }
      const defaultText = apiKeySubmitBtn.dataset.defaultText || 'Change';
      const myanmarText = apiKeySubmitBtn.dataset.myanmarText || defaultText;
      const currentLang = window.currentLanguage || 'en';
      return currentLang === 'my' ? myanmarText : defaultText;
    };

    const updateApiKeyButtonLabel = () => {
      apiKeySubmitBtn.textContent = getChangeLabel();
    };

    updateApiKeyButtonLabel();
    document.addEventListener('languagechange', updateApiKeyButtonLabel);

    apiKeySubmitBtn.addEventListener('click', async () => {
      const newKey = apiKeyInput.value.trim();
      if (!newKey) {
        notify.warning('Please enter a Gemini API key.', 'Missing API Key');
        apiKeyInput.focus();
        return;
      }

      try {
        apiKeySubmitBtn.disabled = true;
        const savingText =
          typeof window.getTranslation === 'function'
            ? window.getTranslation('Saving...')
            : 'Saving...';
        apiKeySubmitBtn.textContent = savingText;

        const response = await fetch('/api/update-api-key', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ apiKey: newKey }),
        });

        const data = await response.json();

        if (!response.ok || !data.success) {
          const errorMessage = data.error || 'Failed to update API key.';
          notify.error(errorMessage, 'Update Failed');
          return;
        }

        apiKeyBtn.dataset.currentKey = newKey;
        closeApiKeyModal();
        notify.success('API key updated successfully!', 'Success');
      } catch (error) {
        console.error('Failed to update API key:', error);
        notify.error('Could not update API key. Please try again.', 'Network Error');
      } finally {
        updateApiKeyButtonLabel();
        apiKeySubmitBtn.disabled = false;
      }
    });
  }

  // Word count select is ready to use - no additional functionality needed
  // Writing style select is ready to use - no additional functionality needed

  // Reference Links functionality removed

  // Emoji Toggle functionality (simplified for new toggle switch)
  const emojiToggle = document.getElementById('emoji-toggle');
  // No additional JS needed - CSS handles the toggle visual state

  // Image Preview functionality
  const imageUpload = document.getElementById('image-upload');
  const imagePreviewContainer = document.getElementById('image-preview-container');
  const imagePreview = document.getElementById('image-preview');
  const removeImageBtn = document.getElementById('remove-image-btn');
  const imageUploadArea = document.getElementById('image-upload-area');

  if (imageUpload && imagePreview && imagePreviewContainer && removeImageBtn) {
    // Handle image selection
    imageUpload.addEventListener('change', function (e) {
      const file = e.target.files[0];
      if (file) {
        // Validate file type
        const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp'];
        if (!allowedTypes.includes(file.type)) {
          notify.error(
            'JPG, PNG, သို့မဟုတ် WebP ပုံဖိုင်တွေပဲ upload လုပ်နိုင်ပါတယ်။',
            'Invalid File Type'
          );
          imageUpload.value = '';
          return;
        }

        // Validate file size (4MB)
        const maxSize = 4 * 1024 * 1024;
        if (file.size > maxSize) {
          notify.error(
            'ပုံဖိုင်က အရမ်းကြီးလွန်းပါတယ်။ 4MB ထက်နည်းတဲ့ ပုံကို သုံးပါ။',
            'File Too Large'
          );
          imageUpload.value = '';
          return;
        }

        // Show preview
        const reader = new FileReader();
        reader.onload = function (e) {
          imagePreview.src = e.target.result;
          imagePreviewContainer.style.display = 'block';
          imageUploadArea.style.display = 'none';
        };
        reader.readAsDataURL(file);
      }
    });

    // Handle remove image
    removeImageBtn.addEventListener('click', function () {
      imageUpload.value = '';
      imagePreview.src = '';
      imagePreviewContainer.style.display = 'none';
      imageUploadArea.style.display = 'flex';
    });
  }

  // Generate content functionality
  generateBtn.addEventListener('click', async function () {
    const pageName = document.getElementById('page-name').value;
    const prompt = document.getElementById('prompt').value;
    const purpose = document.getElementById('purpose').value;

    // Get selected writing style from select dropdown
    const writingStyle = document.getElementById('writing-style').value;

    const audience = document.getElementById('audience').value;
    const keywords = document.getElementById('keywords').value;
    const hashtags = document.getElementById('hashtags').value;
    const cta = document.getElementById('cta').value;
    const negativeConstraints = document.getElementById('negative-constraints').value;

    if (!pageName.trim()) {
      notify.warning(
        'Content ခေါင်းစဉ် ထည့်ပါ။ ဒါမှ content ကို generate လုပ်နိုင်မှာပါ။',
        'Missing Content Title'
      );
      return;
    }

    if (!prompt.trim()) {
      notify.warning('Topic ထည့်ပါ။ ဒါမှ content ကို generate လုပ်နိုင်မှာပါ။', 'Missing Topic');
      return;
    }

    if (!purpose || purpose.trim() === '') {
      notify.warning(
        'Purpose ရွေးချယ်ပါ။ ဒါမှ content ကို generate လုပ်နိုင်မှာပါ။',
        'Missing Purpose'
      );
      return;
    }

    if (!audience.trim()) {
      notify.warning(
        'Audience ထည့်ပါ။ ဒါမှ content ကို generate လုပ်နိုင်မှာပါ။',
        'Missing Audience'
      );
      return;
    }

    if (!writingStyle || writingStyle.trim() === '') {
      notify.warning(
        'Writing Style ရွေးချယ်ပါ။ ဒါမှ content ကို generate လုပ်နိုင်မှာပါ။',
        'Missing Writing Style'
      );
      return;
    }

    const wordCount = document.getElementById('word-count').value;
    if (!wordCount || wordCount.trim() === '') {
      notify.warning(
        'Content Length ရွေးချယ်ပါ။ ဒါမှ content ကို generate လုပ်နိုင်မှာပါ။',
        'Missing Content Length'
      );
      return;
    }

    const language = document.getElementById('language').value;
    if (!language || language.trim() === '') {
      notify.warning(
        'Output Language ရွေးချယ်ပါ။ ဒါမှ content ကို generate လုပ်နိုင်မှာပါ။',
        'Missing Output Language'
      );
      return;
    }

    try {
      showLoadingAnimation();

      // Set loading state
      generateBtn.disabled = true;
      generateSpinner.classList.remove('hidden');
      if (generateMagicIcon) {
        generateMagicIcon.classList.add('hidden');
      }
      const generatingText = window.getTranslation
        ? window.getTranslation('Generating...')
        : 'Generating...';
      generateBtnText.textContent = generatingText;
      contentArea.value = '';
      saveContentBtn.disabled = true;

      // Disable navigation links during generation
      disableNavigationLinks();

      const formData = new FormData();
      formData.append('pageName', pageName);
      formData.append('prompt', prompt);
      formData.append('purpose', purpose);
      formData.append('writingStyle', writingStyle);
      formData.append('audience', audience);
      formData.append('wordCount', wordCount);
      formData.append('keywords', keywords);
      formData.append('hashtags', hashtags);
      formData.append('cta', cta);
      formData.append('negativeConstraints', negativeConstraints);
      formData.append('language', language);

      // Add emoji toggle state
      const includeEmojis = document.getElementById('emoji-toggle').checked;
      formData.append('includeEmojis', includeEmojis);

      const imageFile = document.getElementById('image-upload').files[0];
      if (imageFile) {
        // Check file size (reduce to 4MB for better compatibility)
        const maxSize = 4 * 1024 * 1024; // 4MB
        if (imageFile.size > maxSize) {
          notify.error(
            'ပုံဖိုင်က အရမ်းကြီးလွန်းပါတယ်။ 4MB ထက်နည်းတဲ့ ပုံကို သုံးပါ။',
            'File Too Large'
          );
          return;
        }

        // Check file type
        const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp'];
        if (!allowedTypes.includes(imageFile.type)) {
          notify.error(
            'JPG, PNG, သို့မဟုတ် WebP ပုံဖိုင်တွေပဲ upload လုပ်နိုင်ပါတယ်။',
            'Invalid File Type'
          );
          return;
        }

        formData.append('image', imageFile);
      }

      const response = await fetch('/generate-content', {
        method: 'POST',
        body: formData,
      });

      const data = await response.json();

      // Check if response has error
      if (data.error) {
        // Translate error message if available
        const translatedError = window.getTranslation
          ? window.getTranslation(data.error)
          : data.error;

        // Handle specific error cases
        if (response.status === 413) {
          notify.error('ပုံဖိုင်က အရမ်းကြီးလွန်းပါတယ်။ ပိုသေးတဲ့ ပုံကို သုံးပါ။', 'File Too Large');
        } else if (response.status === 403) {
          notify.error(translatedError, 'Limit Reached');
        } else {
          notify.error(translatedError, 'Generation Failed');
        }
      } else {
        contentArea.value = data.content;

        // Show the content area and hide the empty state
        if (generatedContentDisplay) {
          generatedContentDisplay.style.display = 'none';
        }
        contentArea.style.display = 'block';

        // Show and enable buttons
        saveContentBtn.style.display = 'inline-flex';
        saveContentBtn.disabled = false;
        if (copyContentBtn) {
          copyContentBtn.style.display = 'inline-flex';
        }

        // Update content counts immediately after generation
        if (data.remaining_count !== undefined) {
          updateContentCounts(data.remaining_count, data.total_generated);
        }

        notify.success('Content generated successfully!', 'Success');
      }
    } catch (error) {
      console.error('Error:', error);
      notify.error('An error occurred while generating content', 'Network Error');
    } finally {
      hideLoadingAnimation();

      // Reset loading state
      generateBtn.disabled = false;
      generateSpinner.classList.add('hidden');
      if (generateMagicIcon) {
        generateMagicIcon.classList.remove('hidden');
      }
      const generateText = window.getTranslation
        ? window.getTranslation('Generate Content')
        : 'Generate Content';
      generateBtnText.textContent = generateText;

      // Re-enable navigation links after generation
      enableNavigationLinks();
    }
  });

  // Save content functionality
  saveContentBtn.addEventListener('click', async function () {
    const content = contentArea.value;
    const pageName = document.getElementById('page-name').value;
    const promptText = document.getElementById('prompt').value.substring(0, 50);

    if (!content.trim()) {
      notify.warning('No content to save', 'Missing Content');
      return;
    }

    // Use page name as default title, fallback to prompt
    const defaultTitle = pageName.trim() || promptText.substring(0, 50);

    // Create a modal for saving content
    const promptMessage = window.getTranslation
      ? window.getTranslation('Enter a title for this content:')
      : 'Enter a title for this content:';

    const modalTitle = window.getTranslation
      ? window.getTranslation('Save Content')
      : 'Save Content';

    const title = await modal.prompt(promptMessage, modalTitle, defaultTitle, 'Content title...', {
      required: true,
    });

    if (title) {
      try {
        saveContentBtn.disabled = true;
        const saveTextSpan = saveContentBtn.querySelector('.save-text');
        if (saveTextSpan) {
          const savingText = window.getTranslation
            ? window.getTranslation('Saving...')
            : 'Saving...';
          saveTextSpan.textContent = savingText;
        }

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
        formData.append(
          'negative_constraints',
          document.getElementById('negative-constraints').value
        );

        const response = await fetch('/contents/save', {
          method: 'POST',
          body: formData,
        });

        const data = await response.json();

        if (data.success) {
          notify.success('Content saved successfully!', 'Saved');

          // Update total content count
          updateTotalContentCount();

          // Note: Recent Content section has been removed from the UI
          // addToRecentContentList(data.content);
          // refreshRecentContent();

          // Clear the content area and reset form
          contentArea.value = '';
          contentArea.style.display = 'none';
          if (generatedContentDisplay) {
            generatedContentDisplay.style.display = 'flex';
          }

          // Hide save and copy buttons
          saveContentBtn.style.display = 'none';
          saveContentBtn.disabled = true;
          if (copyContentBtn) {
            copyContentBtn.style.display = 'none';
          }

          // Reset form fields
          document.getElementById('page-name').value = '';
          document.getElementById('prompt').value = '';

          // Reset save button text
          const saveTextSpan = saveContentBtn.querySelector('.save-text');
          if (saveTextSpan) {
            const saveText = window.getTranslation ? window.getTranslation('Save') : 'Save';
            saveTextSpan.textContent = saveText;
          }
        } else {
          notify.error(data.error || 'An error occurred', 'Save Failed');
        }
      } catch (error) {
        console.error('Error:', error);
        notify.error('An error occurred while saving content', 'Network Error');
      } finally {
        saveContentBtn.disabled = false;
        const saveTextSpan = saveContentBtn.querySelector('.save-text');
        if (saveTextSpan) {
          const saveText = window.getTranslation ? window.getTranslation('Save') : 'Save';
          saveTextSpan.textContent = saveText;
        }
      }
    }
  });

  // Copy content functionality
  if (copyContentBtn) {
    copyContentBtn.addEventListener('click', async function () {
      const content = contentArea.value;

      if (!content || content.trim() === '') {
        notify.warning('No content to copy', 'Empty Content');
        return;
      }

      try {
        // Use Clipboard API
        await navigator.clipboard.writeText(content);

        // Update button text temporarily
        const textSpan = copyContentBtn.querySelector('span');
        const originalText = textSpan.textContent;

        // Get translated text
        const copiedText =
          typeof window.getTranslation === 'function'
            ? window.getTranslation('Copied!')
            : 'Copied!';

        textSpan.textContent = copiedText;

        // Show success notification
        notify.success('Content copied to clipboard!', 'Copy Success');

        // Reset button text after 2 seconds
        setTimeout(() => {
          const copyText =
            typeof window.getTranslation === 'function' ? window.getTranslation('Copy') : 'Copy';

          const textSpan = copyContentBtn.querySelector('span');
          if (textSpan) {
            textSpan.textContent = copyText;
          }
        }, 2000);
      } catch (error) {
        console.error('Error copying content:', error);

        // Fallback for older browsers
        try {
          contentArea.select();
          document.execCommand('copy');
          notify.success('Content copied to clipboard!', 'Copy Success');
        } catch (fallbackError) {
          notify.error(
            'Failed to copy content. Please try selecting and copying manually.',
            'Copy Failed'
          );
        }
      }
    });
  }
});

// Function to update content counts after generation
function updateContentCounts(remainingCount, totalGenerated) {
  // Update remaining content count for non-admin users
  const remainingContentElement = document.querySelector(
    '.bg-gradient-to-r.from-blue-600 p.text-2xl'
  );
  if (remainingContentElement) {
    // Check if it's showing infinity symbol for normal users or if remaining count is "unlimited"
    if (remainingContentElement.textContent === '∞' || remainingCount === 'unlimited') {
      // Keep showing infinity for normal users
      remainingContentElement.textContent = '∞';
    } else {
      // Update count for trial users
      remainingContentElement.textContent = remainingCount;
    }
  }

  // Update credit count in desktop menu
  updateMenuCreditCount(remainingCount);

  // Show warning if user is running low on content generations (only for trial users with numeric count)
  if (typeof remainingCount === 'number') {
    if (remainingCount <= 1 && remainingCount > 0) {
      notify.warning(
        `You have ${remainingCount} content generation remaining. Your account will expire in 1 day.`,
        'Low Content Count'
      );
    }
  }
}

// Function to update credit count in menu
function updateMenuCreditCount(remainingCount) {
  // Skip if unlimited/infinity
  if (remainingCount === 'unlimited' || remainingCount === '∞') {
    return;
  }

  // Update desktop menu credit count by ID
  const desktopCreditCount = document.getElementById('desktop-menu-credit-count');
  if (desktopCreditCount) {
    desktopCreditCount.textContent = remainingCount;
  }

  // Update mobile menu credit count by ID
  const mobileCreditCount = document.getElementById('mobile-menu-credit-count');
  if (mobileCreditCount) {
    mobileCreditCount.textContent = remainingCount;
  }
}

// Function to update total content count (for saved content)
function updateTotalContentCount() {
  // Look for the total count in the red gradient box (saved content count)
  const totalContentElement = document.querySelector('.bg-gradient-to-r.from-red-600 p.text-3xl');
  if (totalContentElement) {
    const currentCount = parseInt(totalContentElement.textContent) || 0;
    totalContentElement.textContent = currentCount + 1;
  }
}

// Function to add new content to recent content list (DEPRECATED - Recent Content section removed)
function addToRecentContentList(contentData) {
  // This function is no longer used as Recent Content section has been removed
  return;

  // Find the Recent Content section first, then look for the content list inside it
  const recentContentSection = document.querySelector('h2[data-translate="Recent Content"]');
  let recentContentList = null;

  if (recentContentSection) {
    // Find the parent container of the Recent Content section
    const sectionContainer = recentContentSection.closest('.backdrop-blur-sm');
    if (sectionContainer) {
      // Look for the space-y-3 container inside this section
      recentContentList = sectionContainer.querySelector('.space-y-3');
    }
  }

  // Fallback to original selector if the above doesn't work
  if (!recentContentList) {
    recentContentList = document.querySelector('.space-y-3');
  }

  // If no recent content list exists, we need to create it and replace the "no content" message
  if (!recentContentList) {
    // Find the "no content" message specifically in the Recent Content section
    let noContentMessage = null;
    if (recentContentSection) {
      const sectionContainer = recentContentSection.closest('.backdrop-blur-sm');
      if (sectionContainer) {
        noContentMessage = sectionContainer.querySelector('.text-gray-500.text-center.py-8');
      }
    }

    // Fallback to global search
    if (!noContentMessage) {
      noContentMessage = document.querySelector('.text-gray-500.text-center.py-8');
    }

    if (noContentMessage) {
      // Create the recent content container
      recentContentList = document.createElement('div');
      recentContentList.className = 'space-y-3';

      // Replace the "no content" message with our new container
      noContentMessage.parentNode.replaceChild(recentContentList, noContentMessage);
    }
  }

  if (recentContentList && contentData) {
    // Create new content item matching the template structure
    const contentItem = document.createElement('div');
    contentItem.className = 'border-l-4 border-red-600 pl-4 py-2';

    // Format the current date/time in DD/MM/YY HH:MM format
    const now = new Date();
    const day = String(now.getDate()).padStart(2, '0');
    const month = String(now.getMonth() + 1).padStart(2, '0');
    const year = String(now.getFullYear()).slice(-2);
    const hours = String(now.getHours()).padStart(2, '0');
    const minutes = String(now.getMinutes()).padStart(2, '0');
    const timeString = `${day}/${month}/${year} ${hours}:${minutes}`;

    contentItem.innerHTML = `
      <div class="flex flex-col sm:flex-row sm:justify-between sm:items-start space-y-2 sm:space-y-0">
        <div class="flex-1 min-w-0">
          <h3 class="font-medium">
            <a href="/contents/${contentData.id}" class="hover:text-red-300 block sm:inline">
              ${contentData.title}
            </a>
          </h3>
          <p class="text-sm break-words">${contentData.content.substring(0, 60)}${
      contentData.content.length > 60 ? '...' : ''
    }</p>
          <p class="text-xs">${timeString}</p>
        </div>
        <span class="inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-red-600 text-white self-start sm:ml-4">
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
  }
}

// Function to disable navigation links during content generation
function disableNavigationLinks() {
  // Find all navigation links (including voice generator)
  const navLinks = document.querySelectorAll(
    'a[href*="dashboard"], a[href*="content"], a[href*="history"], a[href*="voice"]'
  );

  navLinks.forEach(link => {
    // Store original href and onclick
    link.dataset.originalHref = link.href;
    if (link.onclick) {
      link.dataset.originalOnclick = link.onclick.toString();
    }

    // Disable the link
    link.href = 'javascript:void(0)';
    link.onclick = function (e) {
      e.preventDefault();
      notify.warning('Please wait for content generation to complete', 'Generation in Progress');
      return false;
    };

    // Add visual indication
    link.style.opacity = '0.5';
    link.style.pointerEvents = 'none';
    link.style.cursor = 'not-allowed';
  });

  // Also disable specific navigation buttons/links
  const specificLinks = [
    'a[href="/dashboard"]',
    'a[href="/contents"]',
    'a[href*="content_history"]',
    'a[href="/voice-generator"]',
    'a[data-translate="View All"]',
    'a[data-translate="Voice Input"]',
  ];

  specificLinks.forEach(selector => {
    const elements = document.querySelectorAll(selector);
    elements.forEach(element => {
      element.dataset.originalHref = element.href;
      element.href = 'javascript:void(0)';
      element.onclick = function (e) {
        e.preventDefault();
        notify.warning('Please wait for content generation to complete', 'Generation in Progress');
        return false;
      };
      element.style.opacity = '0.5';
      element.style.pointerEvents = 'none';
      element.style.cursor = 'not-allowed';
    });
  });
}

// Function to re-enable navigation links after content generation
function enableNavigationLinks() {
  // Find all navigation links
  const navLinks = document.querySelectorAll('a[data-original-href]');

  navLinks.forEach(link => {
    // Restore original href
    if (link.dataset.originalHref) {
      link.href = link.dataset.originalHref;
      delete link.dataset.originalHref;
    }

    // Restore original onclick if it existed
    if (link.dataset.originalOnclick) {
      link.onclick = new Function(link.dataset.originalOnclick);
      delete link.dataset.originalOnclick;
    } else {
      link.onclick = null;
    }

    // Remove visual indication
    link.style.opacity = '';
    link.style.pointerEvents = '';
    link.style.cursor = '';
  });

  // Also re-enable specific navigation buttons/links
  const specificLinks = ['a[href="javascript:void(0)"]'];

  specificLinks.forEach(selector => {
    const elements = document.querySelectorAll(selector);
    elements.forEach(element => {
      if (element.dataset.originalHref) {
        element.href = element.dataset.originalHref;
        delete element.dataset.originalHref;
        element.onclick = null;
        element.style.opacity = '';
        element.style.pointerEvents = '';
        element.style.cursor = '';
      }
    });
  });
}

// Function to refresh recent content section by reloading the page section (DEPRECATED)
async function refreshRecentContent() {
  // This function is no longer used as Recent Content section has been removed
  return;

  try {
    // Simple approach: reload just this section of the page
    const currentUrl = window.location.href;
    const response = await fetch(currentUrl);

    if (response.ok) {
      const html = await response.text();
      const parser = new DOMParser();
      const doc = parser.parseFromString(html, 'text/html');

      // Find the recent content section in the new HTML
      const newRecentSection = doc.querySelector('h2[data-translate="Recent Content"]');
      if (newRecentSection) {
        const newSectionContainer = newRecentSection.closest('.backdrop-blur-sm');

        // Find the current recent content section
        const currentRecentSection = document.querySelector('h2[data-translate="Recent Content"]');
        if (currentRecentSection) {
          const currentSectionContainer = currentRecentSection.closest('.backdrop-blur-sm');

          if (newSectionContainer && currentSectionContainer) {
            // Replace the entire section
            currentSectionContainer.innerHTML = newSectionContainer.innerHTML;
          }
        }
      }
    }
  } catch (error) {
    // Silent error handling
  }
}

// Function to cleanup expired users (Admin only)
async function cleanupExpiredUsers() {
  const cleanupBtn = document.getElementById('cleanup-expired-btn');
  if (!cleanupBtn) return;

  try {
    // Disable button and show loading state
    cleanupBtn.disabled = true;
    cleanupBtn.textContent = 'Running cleanup...';
    cleanupBtn.classList.add('opacity-75');

    const response = await fetch('/admin/cleanup-expired-users', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    const data = await response.json();

    if (data.success) {
      if (window.notify) {
        notify.success(
          `Successfully deleted ${data.deleted_count} expired user accounts`,
          'Cleanup Complete'
        );
      } else {
        alert(`Successfully deleted ${data.deleted_count} expired user accounts`);
      }

      // Refresh the page to update user list
      setTimeout(() => {
        window.location.reload();
      }, 1500);
    } else {
      if (window.notify) {
        notify.error(data.error || 'Failed to cleanup expired users', 'Cleanup Failed');
      } else {
        alert(data.error || 'Failed to cleanup expired users');
      }
    }
  } catch (error) {
    console.error('Error:', error);
    if (window.notify) {
      notify.error('An error occurred while cleaning up expired users', 'Network Error');
    } else {
      alert('An error occurred while cleaning up expired users');
    }
  } finally {
    // Reset button state
    cleanupBtn.disabled = false;
    cleanupBtn.textContent = 'Manual Cleanup Now';
    cleanupBtn.classList.remove('opacity-75');
  }
}
