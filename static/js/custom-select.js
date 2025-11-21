// Custom Select Dropdown Component
// Store all instances to manage open/close state
const customSelectInstances = [];

class CustomSelect {
  constructor(selectElement) {
    this.selectElement = selectElement;
    this.selectedIndex = selectElement.selectedIndex;
    this.options = Array.from(selectElement.options);
    this.isOpen = false;
    
    this.createCustomSelect();
    this.addEventListeners();
    
    // Add to instances array
    customSelectInstances.push(this);
  }

  createCustomSelect() {
    // Create wrapper
    this.wrapper = document.createElement('div');
    this.wrapper.className = 'custom-select-wrapper';
    
    // Create custom select button
    this.customSelect = document.createElement('div');
    this.customSelect.className = 'custom-select w-full px-4 py-3 bg-white border-2 border-gray-300 rounded-xl text-gray-900 focus:outline-none focus:border-red-500 hover:border-red-400 transition-colors duration-200 cursor-pointer';
    this.customSelect.setAttribute('tabindex', '0');
    
    // Create selected value display
    this.selectedValue = document.createElement('div');
    this.selectedValue.className = 'custom-select-value';
    this.selectedValue.textContent = this.options[this.selectedIndex].textContent;
    
    // Create arrow icon
    this.arrow = document.createElement('div');
    this.arrow.className = 'custom-select-arrow';
    this.arrow.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg>`;
    
    // Create dropdown list
    this.dropdown = document.createElement('div');
    this.dropdown.className = 'custom-select-dropdown';
    
    // Create options (skip placeholder options with empty value)
    this.options.forEach((option, index) => {
      // Skip placeholder options (empty value and contains "Select" or Myanmar select words)
      if (option.value === '' && (
        option.textContent.toLowerCase().includes('select') || 
        option.textContent.includes('ရွေးချယ်') ||
        option.textContent.includes('ရွေးပါ')
      )) {
        return;
      }
      
      const optionElement = document.createElement('div');
      optionElement.className = 'custom-select-option';
      optionElement.textContent = option.textContent;
      optionElement.dataset.value = option.value;
      optionElement.dataset.index = index;
      
      if (index === this.selectedIndex) {
        optionElement.classList.add('selected');
      }
      
      // Copy data attributes for translation
      if (option.hasAttribute('data-translate')) {
        optionElement.setAttribute('data-translate', option.getAttribute('data-translate'));
      }
      
      this.dropdown.appendChild(optionElement);
    });
    
    // Assemble custom select
    this.customSelect.appendChild(this.selectedValue);
    this.customSelect.appendChild(this.arrow);
    this.wrapper.appendChild(this.customSelect);
    this.wrapper.appendChild(this.dropdown);
    
    // Replace original select
    this.selectElement.style.display = 'none';
    this.selectElement.parentNode.insertBefore(this.wrapper, this.selectElement);
  }

  addEventListeners() {
    // Toggle dropdown
    this.customSelect.addEventListener('click', (e) => {
      e.stopPropagation();
      this.toggleDropdown();
    });

    // Keyboard navigation
    this.customSelect.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        this.toggleDropdown();
      } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        this.selectNext();
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        this.selectPrevious();
      }
    });

    // Select option
    this.dropdown.querySelectorAll('.custom-select-option').forEach(option => {
      option.addEventListener('click', (e) => {
        e.stopPropagation();
        const index = parseInt(option.dataset.index);
        this.selectOption(index);
      });
    });

    // Close dropdown when clicking outside
    document.addEventListener('click', () => {
      this.closeDropdown();
    });
  }

  toggleDropdown() {
    if (this.isOpen) {
      this.closeDropdown();
    } else {
      this.openDropdown();
    }
  }

  openDropdown() {
    // Close all other dropdowns first
    customSelectInstances.forEach(instance => {
      if (instance !== this && instance.isOpen) {
        instance.closeDropdown();
      }
    });
    
    this.isOpen = true;
    this.dropdown.classList.add('open');
    this.arrow.classList.add('open');
  }

  closeDropdown() {
    this.isOpen = false;
    this.dropdown.classList.remove('open');
    this.arrow.classList.remove('open');
  }

  selectOption(index) {
    // Update selected index
    this.selectedIndex = index;
    
    // Update display
    this.selectedValue.textContent = this.options[index].textContent;
    
    // Update dropdown options - compare by data-index attribute
    this.dropdown.querySelectorAll('.custom-select-option').forEach((opt) => {
      const optIndex = parseInt(opt.dataset.index);
      if (optIndex === index) {
        opt.classList.add('selected');
      } else {
        opt.classList.remove('selected');
      }
    });
    
    // Update original select
    this.selectElement.selectedIndex = index;
    
    // Trigger change event
    const event = new Event('change', { bubbles: true });
    this.selectElement.dispatchEvent(event);
    
    // Close dropdown
    this.closeDropdown();
  }

  selectNext() {
    if (this.selectedIndex < this.options.length - 1) {
      this.selectOption(this.selectedIndex + 1);
    }
  }

  selectPrevious() {
    if (this.selectedIndex > 0) {
      this.selectOption(this.selectedIndex - 1);
    }
  }
  
  // Method to update translations
  updateTranslations(language) {
    // Update selected value display
    const selectedOption = this.options[this.selectedIndex];
    const translateKey = selectedOption.getAttribute('data-translate');
    if (translateKey && typeof translations !== 'undefined' && translations[translateKey] && translations[translateKey][language]) {
      this.selectedValue.textContent = translations[translateKey][language];
    }
    
    // Update all dropdown options
    this.dropdown.querySelectorAll('.custom-select-option').forEach(optionElement => {
      const key = optionElement.getAttribute('data-translate');
      if (key && typeof translations !== 'undefined' && translations[key] && translations[key][language]) {
        optionElement.textContent = translations[key][language];
      }
    });
  }
}

// Initialize custom selects when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
  // Wait a bit for other scripts to load
  setTimeout(() => {
    const selects = document.querySelectorAll('select:not([style*="display: none"])');
    selects.forEach(select => {
      // Skip if already initialized
      if (!select.previousElementSibling || !select.previousElementSibling.classList.contains('custom-select-wrapper')) {
        new CustomSelect(select);
      }
    });
  }, 100);
});
