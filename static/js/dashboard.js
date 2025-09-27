// Content Manager - Dashboard JavaScript

// Dashboard specific functionality
document.addEventListener('DOMContentLoaded', function() {
  const generateBtn = document.getElementById('generate-btn');
  const generateSpinner = document.getElementById('generate-spinner');
  const generateBtnText = document.getElementById('generate-btn-text');
  const contentArea = document.getElementById('content-area');
  const saveContentBtn = document.getElementById('save-content-btn');

  if (!generateBtn || !contentArea || !saveContentBtn) {
    return; // Not on dashboard page
  }

  // Generate content functionality
  generateBtn.addEventListener('click', async function() {
    const prompt = document.getElementById('prompt').value;
    const purpose = document.getElementById('purpose').value;
    const writingStyle = document.getElementById('writing-style').value;
    const audience = document.getElementById('audience').value;
    const keywords = document.getElementById('keywords').value;
    const hashtags = document.getElementById('hashtags').value;

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
      formData.append('copywritingModel', document.getElementById('copywriting-model').value);

      const imageFile = document.getElementById('image-upload').files[0];
      if (imageFile) {
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
        
        const formData = new FormData();
        formData.append('title', title);
        formData.append('content', content);
        formData.append('purpose', document.getElementById('purpose').value);
        formData.append('writing_style', document.getElementById('writing-style').value);
        formData.append('audience', document.getElementById('audience').value);
        formData.append('keywords', document.getElementById('keywords').value);
        formData.append('hashtags', document.getElementById('hashtags').value);
        
        const response = await fetch('/contents/save', {
          method: 'POST',
          body: formData
        });
        
        const data = await response.json();
        
        if (data.success) {
          notify.success('Content saved successfully!', 'Saved');
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
