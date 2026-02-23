class VoiceGenerator {
  constructor() {
    this.mediaRecorder = null;
    this.audioChunks = [];
    this.isRecording = false;
    this.recordingTimer = null;
    this.recordingStartTime = null;
    this.stream = null;
    this.selectedImage = null;
    this.audioBlob = null;

    this.initializeElements();
    this.attachEventListeners();
  }

  initializeElements() {
    // Voice recording elements
    this.recordBtn = document.getElementById('voice-record-btn');
    this.micIcon = document.getElementById('mic-icon');
    this.recordBtnText = document.getElementById('record-btn-text');
    this.recordingStatus = document.getElementById('recording-status');
    this.saveStatus = document.getElementById('save-status');
    this.recordingTimerEl = document.getElementById('recording-timer');

    // Image elements
    this.imageUpload = document.getElementById('image-upload');
    this.cameraBtn = document.getElementById('camera-btn');
    this.cameraModal = document.getElementById('camera-modal');
    this.cameraVideo = document.getElementById('camera-video');
    this.cameraCanvas = document.getElementById('camera-canvas');
    this.captureBtn = document.getElementById('capture-btn');
    this.closeCameraBtn = document.getElementById('close-camera');
    this.cancelCameraBtn = document.getElementById('cancel-camera');
    this.imagePreviewContainer = document.getElementById('image-preview-container');
    this.previewImg = document.getElementById('image-preview');
    this.removeImageBtn = document.getElementById('remove-image-btn');

    // Generation elements
    this.generateBtn = document.getElementById('generate-voice-content-btn');
    this.generateSpinner = document.getElementById('generate-voice-spinner');
    this.generateBtnText = document.getElementById('generate-voice-btn-text');
    this.contentArea = document.getElementById('voice-content-area');
    this.saveBtn = document.getElementById('save-voice-content-btn');
    this.saveSpinner = document.getElementById('save-voice-spinner');
    this.saveBtnText = document.getElementById('save-voice-btn-text');

    // Form elements
    this.languageSelect = document.getElementById('language');
    this.wordCountSelect = document.getElementById('word-count');
    this.pageNameInput = document.getElementById('page-name');
    this.purposeInput = document.getElementById('voice-purpose');
  }

  attachEventListeners() {
    // Voice recording with disabled check
    this.recordBtn?.addEventListener('click', e => {
      if (this.recordBtn.disabled) {
        e.preventDefault();
        return false;
      }
      this.toggleRecording();
    });

    // Image handling with disabled check
    this.imageUpload?.addEventListener('change', e => {
      if (this.imageUpload.disabled) {
        e.preventDefault();
        return false;
      }
      this.handleImageUpload(e);
    });

    this.cameraBtn?.addEventListener('click', e => {
      if (this.cameraBtn.disabled) {
        e.preventDefault();
        return false;
      }
      this.openCamera();
    });

    this.closeCameraBtn?.addEventListener('click', () => this.closeCamera());
    this.cancelCameraBtn?.addEventListener('click', () => this.closeCamera());
    this.captureBtn?.addEventListener('click', () => this.capturePhoto());
    this.removeImageBtn?.addEventListener('click', () => this.removeImage());

    // Content generation
    this.generateBtn?.addEventListener('click', e => {
      if (this.generateBtn.disabled) {
        e.preventDefault();
        return false;
      }
      this.generateContent();
    });

    this.saveBtn?.addEventListener('click', e => {
      if (this.saveBtn.disabled) {
        e.preventDefault();
        return false;
      }
      this.saveContent();
    });

    // Enable save button when content is generated
    this.contentArea?.addEventListener('input', () => {
      if (!this.generateBtn.disabled) {
        // Only enable if not generating
        this.saveBtn.disabled = !this.contentArea.value.trim();
      }
    });

    // Copy content button
    const copyBtn = document.getElementById('copy-voice-content-btn');
    if (copyBtn) {
      copyBtn.addEventListener('click', async () => {
        const content = this.contentArea.value.trim();
        if (!content) {
          this.showToast('No content to copy', 'warning');
          return;
        }

        try {
          await navigator.clipboard.writeText(content);

          // Update button text temporarily
          const textSpan = copyBtn.querySelector('.copy-text');
          if (textSpan) {
            const originalText = textSpan.textContent;

            // Get translated text
            const copiedText =
              typeof window.getTranslation === 'function'
                ? window.getTranslation('Copied!')
                : 'Copied!';

            textSpan.textContent = copiedText;

            // Reset after 2 seconds
            setTimeout(() => {
              const copyText =
                typeof window.getTranslation === 'function'
                  ? window.getTranslation('Copy')
                  : 'Copy';

              const textSpan = copyBtn.querySelector('.copy-text');
              if (textSpan) {
                textSpan.textContent = copyText;
              }
            }, 2000);
          }

          this.showToast('Content copied to clipboard!', 'success');
        } catch (err) {
          console.error('Failed to copy:', err);

          // Fallback for older browsers
          try {
            this.contentArea.select();
            document.execCommand('copy');
            this.showToast('Content copied to clipboard!', 'success');
          } catch (fallbackError) {
            this.showToast('Failed to copy content', 'error');
          }
        }
      });
    }
  }

  async toggleRecording() {
    if (this.isRecording) {
      this.stopRecording();
    } else {
      await this.startRecording();
    }
  }

  async startRecording() {
    try {
      this.stream = await navigator.mediaDevices.getUserMedia({
        audio: {
          echoCancellation: true,
          noiseSuppression: true,
          sampleRate: 44100,
        },
      });

      this.mediaRecorder = new MediaRecorder(this.stream, {
        mimeType: 'audio/webm;codecs=opus',
      });

      this.audioChunks = [];
      this.mediaRecorder.ondataavailable = event => {
        if (event.data.size > 0) {
          this.audioChunks.push(event.data);
        }
      };

      this.mediaRecorder.onstop = () => {
        this.saveRecording();
      };

      this.mediaRecorder.start(1000); // Collect data every second
      this.isRecording = true;
      this.recordingStartTime = Date.now();

      this.updateRecordingUI(true);
      this.startTimer();
    } catch (error) {
      console.error('Error starting recording:', error);
      this.showToast('Error accessing microphone. Please check permissions.', 'error');
    }
  }

  stopRecording() {
    if (this.mediaRecorder && this.isRecording) {
      this.mediaRecorder.stop();
      this.isRecording = false;

      if (this.stream) {
        this.stream.getTracks().forEach(track => track.stop());
      }

      this.updateRecordingUI(false);
      this.stopTimer();
    }
  }

  updateRecordingUI(recording) {
    if (recording) {
      this.micIcon.innerHTML = `
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 10a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1h-4a1 1 0 01-1-1v-4z"></path>
            `;
      this.recordBtnText.textContent = 'Stop Recording';
      this.recordBtn.classList.remove('bg-red-600', 'hover:bg-red-700');
      this.recordBtn.classList.add('bg-gray-600', 'hover:bg-gray-700');
      this.recordingStatus.classList.remove('hidden');
    } else {
      this.micIcon.innerHTML = `
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11a7 7 0 01-7 7m0 0a7 7 0 01-7-7m7 7v4m0 0H8m4 0h4m-4-8a3 3 0 01-3-3V5a3 3 0 116 0v6a3 3 0 01-3 3z"></path>
            `;
      this.recordBtnText.textContent = 'Start Recording';
      this.recordBtn.classList.remove('bg-gray-600', 'hover:bg-gray-700');
      this.recordBtn.classList.add('bg-red-600', 'hover:bg-red-700');
      this.recordingStatus.classList.add('hidden');
    }
  }

  startTimer() {
    this.recordingTimer = setInterval(() => {
      const elapsed = Math.floor((Date.now() - this.recordingStartTime) / 1000);
      const minutes = Math.floor(elapsed / 60);
      const seconds = elapsed % 60;
      this.recordingTimerEl.textContent = `${minutes.toString().padStart(2, '0')}:${seconds
        .toString()
        .padStart(2, '0')}`;
    }, 1000);
  }

  stopTimer() {
    if (this.recordingTimer) {
      clearInterval(this.recordingTimer);
      this.recordingTimer = null;
    }
  }

  async saveRecording() {
    if (this.audioChunks.length === 0) {
      this.showToast('No audio recorded. Please try again.', 'error');
      return;
    }

    try {
      const audioBlob = new Blob(this.audioChunks, { type: 'audio/webm' });

      // Check file size
      if (audioBlob.size < 1024) {
        throw new Error('Audio file too small');
      }
      if (audioBlob.size > 10 * 1024 * 1024) {
        throw new Error('Audio file too large (max 10MB)');
      }

      // Store audio blob for later use in content generation
      this.audioBlob = audioBlob;
      this.saveStatus.classList.remove('hidden');
      this.showToast('Voice recording saved successfully!', 'success');
    } catch (error) {
      console.error('Error saving recording:', error);
      this.showToast(error.message || 'Failed to save recording. Please try again.', 'error');
    }
  }

  handleImageUpload(event) {
    const file = event.target.files[0];
    if (file) {
      this.processImageFile(file);
    }
  }

  processImageFile(file) {
    if (!file.type.startsWith('image/')) {
      this.showToast('Please select a valid image file.', 'error');
      return;
    }

    const reader = new FileReader();
    reader.onload = e => {
      this.selectedImage = file;
      this.previewImg.src = e.target.result;
      if (this.imagePreviewContainer) this.imagePreviewContainer.style.display = 'block';
    };
    reader.readAsDataURL(file);
  }

  async openCamera() {
    try {
      // Try to get back camera first, fallback to any available camera
      let stream;
      try {
        stream = await navigator.mediaDevices.getUserMedia({
          video: {
            facingMode: { ideal: 'environment' }, // Back camera
            width: { ideal: 1280 },
            height: { ideal: 720 },
          },
        });
      } catch (backCameraError) {
        // Fallback to any available camera
        stream = await navigator.mediaDevices.getUserMedia({
          video: {
            width: { ideal: 1280 },
            height: { ideal: 720 },
          },
        });
      }

      this.cameraVideo.srcObject = stream;
      this.cameraModal.classList.remove('hidden');
    } catch (error) {
      console.error('Error accessing camera:', error);
      this.showToast('Error accessing camera. Please check permissions.', 'error');
    }
  }

  closeCamera() {
    if (this.cameraVideo.srcObject) {
      const tracks = this.cameraVideo.srcObject.getTracks();
      tracks.forEach(track => track.stop());
      this.cameraVideo.srcObject = null;
    }
    this.cameraModal.classList.add('hidden');
  }

  capturePhoto() {
    const context = this.cameraCanvas.getContext('2d');
    this.cameraCanvas.width = this.cameraVideo.videoWidth;
    this.cameraCanvas.height = this.cameraVideo.videoHeight;

    context.drawImage(this.cameraVideo, 0, 0);

    this.cameraCanvas.toBlob(
      blob => {
        this.selectedImage = new File([blob], 'camera-photo.jpg', { type: 'image/jpeg' });
        this.previewImg.src = URL.createObjectURL(blob);
        if (this.imagePreviewContainer) this.imagePreviewContainer.style.display = 'block';
        this.closeCamera();
        this.showToast('Photo captured successfully!', 'success');
      },
      'image/jpeg',
      0.8
    );
  }

  removeImage() {
    this.selectedImage = null;
    if (this.imagePreviewContainer) this.imagePreviewContainer.style.display = 'none';
    this.imageUpload.value = '';
  }

  async generateContent() {
    // Check if page name is provided first
    const pageName = this.pageNameInput.value.trim();
    if (!pageName) {
      this.showToast('Please enter a content title.', 'error');
      this.pageNameInput.focus();
      return;
    }

    // Check if purpose is selected
    const purpose = this.purposeInput.value;
    if (!purpose || purpose.trim() === '') {
      this.showToast('Purpose ရွေးချယ်ပါ။ ဒါမှ content ကို generate လုပ်နိုင်မှာပါ။', 'error');
      this.purposeInput.focus();
      return;
    }

    // Check if content length is selected
    const wordCount = this.wordCountSelect.value;
    if (!wordCount || wordCount.trim() === '') {
      this.showToast(
        'Content Length ရွေးချယ်ပါ။ ဒါမှ content ကို generate လုပ်နိုင်မှာပါ။',
        'error'
      );
      this.wordCountSelect.focus();
      return;
    }

    // Check if output language is selected
    const language = this.languageSelect.value;
    if (!language || language.trim() === '') {
      this.showToast(
        'Output Language ရွေးချယ်ပါ။ ဒါမှ content ကို generate လုပ်နိုင်မှာပါ။',
        'error'
      );
      this.languageSelect.focus();
      return;
    }

    // Check if we have either voice recording or image
    if (!this.selectedImage && !this.audioBlob) {
      this.showToast('Please record voice or add an image to generate content.', 'error');
      return;
    }

    this.setGeneratingState(true);

    try {
      const formData = new FormData();
      formData.append(
        'prompt',
        'Generate content based on the provided voice recording and/or image'
      );
      formData.append('language', language);
      formData.append('wordCount', wordCount);
      formData.append('pageName', pageName);
      formData.append('purpose', purpose);
      formData.append('audience', 'General Audience');
      formData.append('writingStyle', 'conversational');
      formData.append('keywords', '');
      formData.append('hashtags', '');
      formData.append('cta', '');
      formData.append('negativeConstraints', '');
      formData.append('includeEmojis', 'true');

      // Add audio file if available
      if (this.audioBlob) {
        formData.append('audio', this.audioBlob, 'recording.webm');
      }

      if (this.selectedImage) {
        formData.append('image', this.selectedImage);
      }

      const response = await fetch('/generate-content', {
        method: 'POST',
        body: formData,
      });

      const result = await response.json();

      // Check if response has error
      if (result.error) {
        // Translate error message if available
        const translatedError = window.getTranslation
          ? window.getTranslation(result.error)
          : result.error;
        this.showToast(translatedError, 'error');
      } else if (result.content) {
        this.contentArea.value = result.content;
        this.saveBtn.disabled = false;

        // Show textarea and hide empty state
        const emptyState = document.getElementById('voice-generated-content-display');
        if (emptyState) emptyState.style.display = 'none';
        this.contentArea.style.display = 'block';

        // Show buttons
        if (this.saveBtn) this.saveBtn.style.display = 'inline-flex';
        const copyBtn = document.getElementById('copy-voice-content-btn');
        if (copyBtn) copyBtn.style.display = 'inline-flex';

        this.showToast('Content generated successfully!', 'success');

        // Hide the save status after content is generated
        this.saveStatus.classList.add('hidden');
        this.audioBlob = null;

        // Update remaining content count immediately using server response
        if (result.remaining_count !== undefined) {
          this.updateRemainingCountWithValue(result.remaining_count);
        } else {
          this.updateRemainingCount();
        }
      } else {
        this.showToast('Failed to generate content. Please try again.', 'error');
      }
    } catch (error) {
      console.error('Error generating content:', error);
      this.showToast('An error occurred while generating content. Please try again.', 'error');
    } finally {
      this.setGeneratingState(false);
    }
  }

  setGeneratingState(generating) {
    const wandIcon = document.getElementById('generate-voice-wand-icon');
    const loadingOverlay = document.getElementById('voice-loading-overlay');

    if (generating) {
      // Show loading overlay
      if (loadingOverlay) {
        loadingOverlay.style.display = 'flex';
      }

      // Disable all interactive elements
      if (this.generateBtn) this.generateBtn.disabled = true;
      if (this.recordBtn) this.recordBtn.disabled = true;
      if (this.imageUpload) this.imageUpload.disabled = true;
      if (this.cameraBtn) this.cameraBtn.disabled = true;
      if (this.languageSelect) this.languageSelect.disabled = true;
      if (this.wordCountSelect) this.wordCountSelect.disabled = true;
      if (this.pageNameInput) this.pageNameInput.disabled = true;
      if (this.purposeInput) this.purposeInput.disabled = true;
      if (this.saveBtn) this.saveBtn.disabled = true;

      // Add visual indication that buttons are disabled
      if (this.recordBtn) this.recordBtn.classList.add('opacity-50', 'cursor-not-allowed');
      if (this.cameraBtn) this.cameraBtn.classList.add('opacity-50', 'cursor-not-allowed');

      // Hide wand icon and show spinner
      if (wandIcon) wandIcon.classList.add('hidden');
      if (this.generateSpinner) this.generateSpinner.classList.remove('hidden');

      // Get translated text using current language
      if (this.generateBtnText) {
        const currentLang = window.currentLanguage || 'en';
        this.generateBtnText.textContent =
          typeof window.getTranslation === 'function'
            ? window.getTranslation('Generating...', currentLang)
            : 'Generating...';
      }

      // Disable navigation links during generation
      this.disableNavigationLinks();
    } else {
      // Hide loading overlay
      if (loadingOverlay) {
        loadingOverlay.style.display = 'none';
      }

      // Re-enable all interactive elements
      if (this.generateBtn) this.generateBtn.disabled = false;
      if (this.recordBtn) this.recordBtn.disabled = false;
      if (this.imageUpload) this.imageUpload.disabled = false;
      if (this.cameraBtn) this.cameraBtn.disabled = false;
      if (this.languageSelect) this.languageSelect.disabled = false;
      if (this.wordCountSelect) this.wordCountSelect.disabled = false;
      if (this.pageNameInput) this.pageNameInput.disabled = false;
      if (this.purposeInput) this.purposeInput.disabled = false;

      // Remove visual indication
      if (this.recordBtn) this.recordBtn.classList.remove('opacity-50', 'cursor-not-allowed');
      if (this.cameraBtn) this.cameraBtn.classList.remove('opacity-50', 'cursor-not-allowed');

      // Show wand icon and hide spinner
      if (wandIcon) wandIcon.classList.remove('hidden');
      if (this.generateSpinner) this.generateSpinner.classList.add('hidden');

      // Get translated text using current language
      if (this.generateBtnText) {
        const currentLang = window.currentLanguage || 'en';
        this.generateBtnText.textContent =
          typeof window.getTranslation === 'function'
            ? window.getTranslation('Generate Content', currentLang)
            : 'Generate Content';
      }

      // Re-enable navigation links after generation
      this.enableNavigationLinks();
    }
  }

  async saveContent() {
    const content = this.contentArea.value.trim();
    const pageName = this.pageNameInput.value.trim();
    const promptText = this.transcribedText || 'Voice Generated Content';

    if (!content) {
      const warningMessage = window.getTranslation
        ? window.getTranslation('No content to save')
        : 'No content to save';
      this.showToast(warningMessage, 'warning');
      return;
    }

    // Use page name as default title, fallback to prompt
    const defaultTitle = pageName || promptText.substring(0, 50);

    // Create a modal for saving content
    const promptMessage = window.getTranslation
      ? window.getTranslation('Enter a title for this content:')
      : 'Enter a title for this content:';

    const modalTitle = window.getTranslation
      ? window.getTranslation('Save Content')
      : 'Save Content';

    const confirmButtonText = window.getTranslation ? window.getTranslation('Save') : 'Save';

    const title = await modal.prompt(promptMessage, modalTitle, defaultTitle, 'Content title...', {
      required: true,
      confirmText: confirmButtonText,
    });

    if (!title) {
      return; // User cancelled
    }

    try {
      this.saveBtn.disabled = true;
      const saveTextSpan = this.saveBtn.querySelector('.save-text');
      if (saveTextSpan) {
        const savingText = window.getTranslation ? window.getTranslation('Saving...') : 'Saving...';
        saveTextSpan.textContent = savingText;
      }

      const formData = new FormData();
      formData.append('title', title);
      formData.append('content', content);
      const purpose = this.purposeInput.value || 'General';
      formData.append('purpose', purpose);
      formData.append('writing_style', 'conversational');
      formData.append('audience', 'General Audience');
      formData.append('keywords', '');
      formData.append('hashtags', '');
      formData.append('cta', '');
      formData.append('negative_constraints', '');

      const response = await fetch('/contents/save', {
        method: 'POST',
        body: formData,
      });

      const result = await response.json();

      if (response.ok && result.success) {
        const successMessage = window.getTranslation
          ? window.getTranslation('Content saved successfully!')
          : 'Content saved successfully!';
        this.showToast(successMessage, 'success');

        // Update total content count
        this.updateTotalContentCount();

        // Reset form
        setTimeout(() => {
          this.resetForm();
        }, 1000);
      } else {
        throw new Error(result.error || 'Failed to save content');
      }
    } catch (error) {
      console.error('Error saving content:', error);
      const errorMessage = window.getTranslation
        ? window.getTranslation('An error occurred while saving content')
        : 'An error occurred while saving content';
      this.showToast(error.message || errorMessage, 'error');
    } finally {
      this.saveBtn.disabled = false;
      const saveTextSpan = this.saveBtn.querySelector('.save-text');
      if (saveTextSpan) {
        const saveText = window.getTranslation ? window.getTranslation('Save') : 'Save';
        saveTextSpan.textContent = saveText;
      }
    }
  }

  updateRemainingCount() {
    // Try multiple selectors to find remaining count element
    const selectors = [
      '.remaining-count',
      '[class*="remaining"]',
      '.text-2xl.font-bold',
      '.bg-blue-600 .text-2xl',
      '.bg-gradient-to-r.from-blue-600 .text-2xl',
    ];

    let remainingElement = null;
    for (const selector of selectors) {
      remainingElement = document.querySelector(selector);
      if (remainingElement && remainingElement.textContent.match(/^\d+$/)) {
        break;
      }
    }

    if (remainingElement) {
      const currentCount = parseInt(remainingElement.textContent);
      if (!isNaN(currentCount) && currentCount > 0) {
        remainingElement.textContent = currentCount - 1;

        // Add visual feedback
        remainingElement.classList.add('animate-pulse');
        setTimeout(() => {
          remainingElement.classList.remove('animate-pulse');
        }, 1000);
      }
    } else {
      // Alternative approach: look for elements that might contain count
      const allElements = document.querySelectorAll('.text-2xl.font-bold');
      for (const element of allElements) {
        const text = element.textContent.trim();
        if (/^\d+$/.test(text)) {
          const count = parseInt(text);
          if (count > 0) {
            element.textContent = count - 1;
            element.classList.add('animate-pulse');
            setTimeout(() => {
              element.classList.remove('animate-pulse');
            }, 1000);
            break;
          }
        }
      }
    }
  }

  updateRemainingCountWithValue(newCount) {
    // Try multiple selectors to find remaining count element - ONLY blue background (remaining count)
    const selectors = [
      '.bg-gradient-to-r.from-blue-600 .text-2xl.font-bold',
      '.bg-gradient-to-r.from-blue-600 p.text-2xl',
      '.bg-blue-600 .text-2xl.font-bold',
      '.remaining-count',
      '[class*="remaining"]',
    ];

    let remainingElement = null;
    for (const selector of selectors) {
      remainingElement = document.querySelector(selector);
      if (
        remainingElement &&
        (remainingElement.textContent.match(/^\d+$/) || remainingElement.textContent === '∞')
      ) {
        break;
      }
    }

    if (remainingElement) {
      // Check if it's showing infinity symbol for normal users or if newCount is "unlimited"
      if (remainingElement.textContent === '∞' || newCount === 'unlimited') {
        // Keep showing infinity for normal users
        remainingElement.textContent = '∞';
      } else {
        // Update count for trial users
        remainingElement.textContent = newCount;
      }

      // Add visual feedback
      remainingElement.classList.add('animate-pulse');
      setTimeout(() => {
        remainingElement.classList.remove('animate-pulse');
      }, 1000);

      // Update credit count in menu
      this.updateMenuCreditCount(newCount);
    } else {
      // Alternative approach: look for elements that might contain count in blue container
      const blueContainers = document.querySelectorAll(
        '.bg-gradient-to-r.from-blue-600, .bg-blue-600'
      );
      for (const container of blueContainers) {
        const countElement = container.querySelector('.text-2xl.font-bold');
        if (
          countElement &&
          (/^\d+$/.test(countElement.textContent.trim()) || countElement.textContent === '∞')
        ) {
          if (countElement.textContent === '∞' || newCount === 'unlimited') {
            countElement.textContent = '∞';
          } else {
            countElement.textContent = newCount;
          }
          countElement.classList.add('animate-pulse');
          setTimeout(() => {
            countElement.classList.remove('animate-pulse');
          }, 1000);
          break;
        }
      }
    }
  }

  // Function to update total content count (for saved content)
  updateTotalContentCount() {
    // Look for the total count in the red gradient box (saved content count)
    const totalContentElement = document.querySelector('.bg-gradient-to-r.from-red-600 p.text-3xl');
    if (totalContentElement) {
      const currentCount = parseInt(totalContentElement.textContent) || 0;
      totalContentElement.textContent = currentCount + 1;
    }
  }

  // Function to add new content to recent content list (DEPRECATED - Recent Content section removed)
  addToRecentContentList(contentData) {
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
                    <a href="/contents/${
                      contentData.id
                    }" class="hover:text-red-300 block sm:inline">
                      ${contentData.title}
                    </a>
                  </h3>
                  <p class="text-sm break-words">${contentData.content.substring(0, 100)}${
                    contentData.content.length > 100 ? '...' : ''
                  }</p>
                  <p class="text-xs">${timeString}</p>
                </div>
                <span class="inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-red-600 text-white self-start sm:ml-4">
                  ${this.getPurposeDisplay(contentData.purpose)}
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

  setSavingState(saving) {
    if (saving) {
      if (this.saveBtn) this.saveBtn.disabled = true;
      if (this.saveSpinner) this.saveSpinner.classList.remove('hidden');
      if (this.saveBtnText) {
        this.saveBtnText.textContent = window.getTranslation
          ? window.getTranslation('Saving...')
          : 'Saving...';
      }
    } else {
      if (this.saveSpinner) this.saveSpinner.classList.add('hidden');
      if (this.saveBtnText) {
        this.saveBtnText.textContent = window.getTranslation
          ? window.getTranslation('Save Content')
          : 'Save Content';
      }
      // Don't re-enable the button here - it will be handled by the success/error logic
    }
  }

  getPurposeDisplay(purpose) {
    const purposeMap = {
      informative: window.getTranslation
        ? window.getTranslation('Informative Content')
        : 'Informative Content',
      engagement: window.getTranslation
        ? window.getTranslation('Audience Engagement')
        : 'Audience Engagement',
      sales: window.getTranslation
        ? window.getTranslation('Product/Service Sales')
        : 'Product/Service Sales',
      emotional: window.getTranslation
        ? window.getTranslation('Emotional Content')
        : 'Emotional Content',
      announcement: window.getTranslation
        ? window.getTranslation('Event/Update Announcement')
        : 'Event/Update Announcement',
      educational: window.getTranslation
        ? window.getTranslation('Educational Content')
        : 'Educational Content',
      showcase: window.getTranslation
        ? window.getTranslation('Product Feature Showcase')
        : 'Product Feature Showcase',
    };
    return purposeMap[purpose] || purpose || 'General';
  }

  resetForm() {
    this.contentArea.value = '';
    this.pageNameInput.value = '';
    this.purposeInput.value = '';
    this.removeImage();
    this.audioChunks = [];
    this.audioBlob = null;
    this.recordingDuration = 0;
    this.recordingTimer = null;

    // Reset recording display
    if (this.recordingTimerEl) {
      this.recordingTimerEl.textContent = '00:00';
    }
    if (this.saveStatus) {
      this.saveStatus.classList.add('hidden');
    }

    // Hide textarea and buttons, show empty state
    this.contentArea.style.display = 'none';
    const emptyState = document.getElementById('voice-generated-content-display');
    if (emptyState) emptyState.style.display = 'flex';

    // Hide buttons
    if (this.saveBtn) this.saveBtn.style.display = 'none';
    const copyBtn = document.getElementById('copy-voice-content-btn');
    if (copyBtn) copyBtn.style.display = 'none';

    // Reset button state
    if (this.saveBtn) this.saveBtn.disabled = true;
  }

  showToast(message, type = 'info') {
    // Create toast notification
    const toast = document.createElement('div');
    toast.className = `fixed top-4 right-4 z-50 px-6 py-3 rounded-lg shadow-lg text-white font-medium transform transition-all duration-300 translate-x-full`;

    switch (type) {
      case 'success':
        toast.classList.add('bg-green-600');
        break;
      case 'error':
        toast.classList.add('bg-red-600');
        break;
      case 'warning':
        toast.classList.add('bg-yellow-600');
        break;
      default:
        toast.classList.add('bg-blue-600');
    }

    toast.textContent = message;
    document.body.appendChild(toast);

    // Animate in
    setTimeout(() => {
      toast.classList.remove('translate-x-full');
    }, 100);

    // Animate out and remove
    setTimeout(() => {
      toast.classList.add('translate-x-full');
      setTimeout(() => {
        document.body.removeChild(toast);
      }, 300);
    }, 4000);
  }

  // Function to disable navigation links during content generation
  disableNavigationLinks() {
    // Find all navigation links (including Generator link which uses user_dashboard route)
    const navLinks = document.querySelectorAll(
      'a[href*="dashboard"], a[href*="content"], a[href*="history"], a[href*="voice"], a[data-translate="Generator"]'
    );

    navLinks.forEach(link => {
      // Store original href and onclick
      if (!link.dataset.originalHref) {
        link.dataset.originalHref = link.href;
      }
      if (link.onclick && !link.dataset.originalOnclick) {
        link.dataset.originalOnclick = link.onclick.toString();
      }

      // Disable the link
      link.href = 'javascript:void(0)';
      link.onclick = e => {
        e.preventDefault();
        e.stopPropagation();
        this.showToast('Please wait for content generation to complete', 'warning');
        return false;
      };

      // Add visual indication
      link.style.opacity = '0.5';
      link.style.pointerEvents = 'none';
      link.style.cursor = 'not-allowed';
    });

    // Also disable links by finding parent <a> tags of specific text elements
    const textSelectors = [
      'span[data-translate="Generator"]',
      'span[data-translate="Generator With Voice"]',
      'span[data-translate="Dashboard"]',
    ];

    textSelectors.forEach(selector => {
      const textElements = document.querySelectorAll(selector);
      textElements.forEach(textElement => {
        // Find parent <a> tag
        const linkElement = textElement.closest('a');
        if (linkElement) {
          if (!linkElement.dataset.originalHref) {
            linkElement.dataset.originalHref = linkElement.href;
          }
          linkElement.href = 'javascript:void(0)';
          linkElement.onclick = e => {
            e.preventDefault();
            e.stopPropagation();
            this.showToast('Please wait for content generation to complete', 'warning');
            return false;
          };
          linkElement.style.opacity = '0.5';
          linkElement.style.pointerEvents = 'none';
          linkElement.style.cursor = 'not-allowed';
        }
      });
    });
  }

  // Function to re-enable navigation links after content generation
  enableNavigationLinks() {
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

    // Also restore specific links that might not have data-original-href
    const allLinks = document.querySelectorAll('a[href="javascript:void(0)"]');
    allLinks.forEach(link => {
      link.style.opacity = '';
      link.style.pointerEvents = '';
      link.style.cursor = '';
    });
  }

  // Function to update credit count in menu
  updateMenuCreditCount(remainingCount) {
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
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  new VoiceGenerator();
});
