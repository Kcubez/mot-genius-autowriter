// Favicon refresh utility to prevent favicon disappearing during route changes
(function() {
    'use strict';
    
    // Store the original favicon URL
    let originalFaviconUrl = null;
    let faviconRefreshTimer = null;
    
    // Function to refresh favicon
    function refreshFavicon() {
        // Remove all existing favicon links first
        const existingFaviconLinks = document.querySelectorAll('link[rel*="icon"]');
        existingFaviconLinks.forEach(link => {
            if (link.parentNode) {
                link.parentNode.removeChild(link);
            }
        });
        
        // Create fresh favicon links
        const timestamp = new Date().getTime();
        const randomId = Math.floor(Math.random() * 99999);
        const faviconUrl = '/static/images/MOT.d21a8f07.png';
        
        // Create multiple favicon links for better browser support
        const faviconConfigs = [
            { rel: 'icon', type: 'image/png', sizes: '32x32' },
            { rel: 'icon', type: 'image/png', sizes: '16x16' },
            { rel: 'shortcut icon', type: 'image/png' },
            { rel: 'apple-touch-icon', sizes: '180x180' }
        ];
        
        faviconConfigs.forEach(config => {
            const link = document.createElement('link');
            link.rel = config.rel;
            link.type = config.type;
            if (config.sizes) link.sizes = config.sizes;
            link.href = `${faviconUrl}?v=3.0&t=${timestamp}&r=${randomId}`;
            document.head.appendChild(link);
        });
        
        console.log('Favicon refreshed with timestamp:', timestamp);
    }
    
    // Function to ensure favicon is always visible
    function ensureFaviconVisible() {
        const faviconLinks = document.querySelectorAll('link[rel*="icon"]');
        
        // Check if any favicon link exists
        if (faviconLinks.length === 0) {
            // Create favicon link if missing
            createFaviconLink();
        } else {
            // Refresh existing favicon links
            refreshFavicon();
        }
    }
    
    // Function to create favicon link if missing
    function createFaviconLink() {
        const head = document.head;
        const faviconUrl = originalFaviconUrl || '/static/images/MOT.d21a8f07.png';
        const timestamp = new Date().getTime();
        
        // Create main favicon link
        const faviconLink = document.createElement('link');
        faviconLink.rel = 'icon';
        faviconLink.type = 'image/png';
        faviconLink.sizes = '32x32';
        faviconLink.href = `${faviconUrl}?v=${timestamp}&refresh=true`;
        head.appendChild(faviconLink);
        
        // Create apple touch icon
        const appleTouchIcon = document.createElement('link');
        appleTouchIcon.rel = 'apple-touch-icon';
        appleTouchIcon.href = `${faviconUrl}?v=${timestamp}&refresh=true`;
        head.appendChild(appleTouchIcon);
    }
    
    // Function to monitor favicon status
    function monitorFavicon() {
        const faviconLinks = document.querySelectorAll('link[rel*="icon"]');
        let faviconLoaded = false;
        
        faviconLinks.forEach(link => {
            if (link.href && link.href.includes('MOT.d21a8f07.png')) {
                // Create a test image to check if favicon loads
                const testImg = new Image();
                testImg.onload = function() {
                    faviconLoaded = true;
                };
                testImg.onerror = function() {
                    console.warn('Favicon failed to load, refreshing...');
                    refreshFavicon();
                };
                testImg.src = link.href;
            }
        });
        
        // If no favicon detected after 1 second, refresh
        setTimeout(() => {
            if (!faviconLoaded) {
                ensureFaviconVisible();
            }
        }, 1000);
    }
    
    // Listen for page navigation events
    function setupNavigationListeners() {
        // Listen for popstate (back/forward navigation)
        window.addEventListener('popstate', function() {
            setTimeout(ensureFaviconVisible, 100);
        });
        
        // Listen for beforeunload (page leaving)
        window.addEventListener('beforeunload', function() {
            // Clear any pending refresh timers
            if (faviconRefreshTimer) {
                clearTimeout(faviconRefreshTimer);
            }
        });
        
        // Listen for page load
        window.addEventListener('load', function() {
            setTimeout(monitorFavicon, 500);
        });
        
        // Listen for DOMContentLoaded
        document.addEventListener('DOMContentLoaded', function() {
            setTimeout(ensureFaviconVisible, 100);
        });
        
        // Periodic check every 5 seconds
        setInterval(function() {
            const faviconLinks = document.querySelectorAll('link[rel*="icon"]');
            if (faviconLinks.length === 0) {
                ensureFaviconVisible();
            }
        }, 5000);
    }
    
    // Initialize favicon management
    function initFaviconManager() {
        // Store original favicon URL from existing links
        const existingFavicon = document.querySelector('link[rel*="icon"]');
        if (existingFavicon && existingFavicon.href) {
            originalFaviconUrl = existingFavicon.href.split('?')[0];
        }
        
        // Setup event listeners
        setupNavigationListeners();
        
        // Initial favicon check
        setTimeout(ensureFaviconVisible, 100);
    }
    
    // Start favicon manager when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initFaviconManager);
    } else {
        initFaviconManager();
    }
    
    // Expose refresh function globally for manual use
    window.refreshFavicon = refreshFavicon;
    window.ensureFaviconVisible = ensureFaviconVisible;
    
})();
