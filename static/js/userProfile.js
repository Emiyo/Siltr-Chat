// Wait for the DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize Bootstrap modal
    const profileModal = new bootstrap.Modal(document.getElementById('userProfileModal'));
    let currentUserId = null;
    
    // Function to format date strings
    function formatDate(dateString) {
        if (!dateString) return 'Not available';
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', { 
            year: 'numeric', 
            month: 'long', 
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    }
    
    // Function to safely update element text content
    function safeSetTextContent(elementId, text) {
        const element = document.getElementById(elementId);
        if (element) {
            element.textContent = text || '';
        }
    }

    // Function to safely update element src attribute
    function safeSetSrc(elementId, src) {
        const element = document.getElementById(elementId);
        if (element) {
            element.src = src || '/static/images/default-avatar.png';
        }
    }

    // Function to update theme preview
    function updateThemePreview(color) {
        document.documentElement.style.setProperty('--primary-color', color);
        document.documentElement.style.setProperty('--primary-transparent', `${color}1A`);
        document.documentElement.style.setProperty('--primary-transparent-hover', `${color}26`);
    }

    // Function to update profile banner
    function updateProfileBanner(color) {
        const banner = document.getElementById('profileBanner');
        if (banner) {
            banner.style.backgroundColor = color;
        }
    }
    
    // Initialize color picker
    const colorPicker = document.getElementById('accentColorPicker');
    if (colorPicker) {
        colorPicker.addEventListener('input', function(e) {
            const color = e.target.value;
            updateThemePreview(color);
            updateProfileBanner(color);
        });
    }
    
    // Function to display user profile - making it globally accessible
    window.displayUserProfile = async function(userId) {
        try {
            if (!userId) {
                console.error('No user ID provided');
                return;
            }
            
            currentUserId = userId;
            console.log('Loading profile for user:', userId);
            
            // Store original content and show loading state
            const content = document.querySelector('.profile-content');
            const originalContent = content ? content.innerHTML : '';
            if (content) {
                content.innerHTML = '<div class="loading-spinner"></div><div class="text-center mt-3">Loading profile...</div>';
            }
            
            try {
                // Fetch user data
                const response = await fetch(`/api/user/by_id/${userId}`);
                if (!response.ok) {
                    const errorData = await response.json();
                    throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
                }
                
                const userData = await response.json();
                console.log('Profile data received:', userData);

                // Only proceed if we have user data
                if (!userData || typeof userData !== 'object') {
                    throw new Error('Invalid user data received');
                }
            
            // Update modal content
            safeSetSrc('profileAvatar', userData.avatar);
            safeSetTextContent('profileUsername', userData.display_name || userData.username);
            safeSetTextContent('profileStatus', userData.status || 'No status set');
            safeSetTextContent('profileBio', userData.bio || 'No bio provided');
            safeSetTextContent('profileLocation', userData.location || 'Location not set');
            safeSetTextContent('profileJoinDate', formatDate(userData.created_at));
            safeSetTextContent('profileLastSeen', formatDate(userData.last_seen));
            
            // Update theme color
            if (userData.accent_color) {
                if (colorPicker) colorPicker.value = userData.accent_color;
                updateThemePreview(userData.accent_color);
                updateProfileBanner(userData.accent_color);
            }
            
            // Show the modal
            profileModal.show();
        if (content) {
                    content.innerHTML = '';  // Clear loading state
                }
            } catch (error) {
                console.error('Error loading user profile:', error);
                if (content) {
                    content.innerHTML = `
                        <div class="alert alert-danger">
                            <strong>Error loading profile:</strong><br>
                            ${error.message || 'Failed to load user profile. Please try again.'}
                        </div>
                    `;
                }
                return;  // Exit early on error
            }
    };
    
    // Event delegation for user profile clicks
    document.body.addEventListener('click', function(event) {
        const userElement = event.target.closest('[data-user-id]');
        if (userElement) {
            event.preventDefault();
            const userId = userElement.dataset.userId;
            window.displayUserProfile(userId);
        }
    });
    
    // Initialize message button handler
    const messageUserBtn = document.getElementById('messageUserBtn');
    if (messageUserBtn) {
        messageUserBtn.addEventListener('click', function() {
            if (currentUserId && typeof socket !== 'undefined') {
                socket.emit('start_direct_message', { target_user_id: currentUserId });
                profileModal.hide();
            }
        });
    }

    // Modal cleanup handler
    const modalElement = document.getElementById('userProfileModal');
    if (modalElement) {
        modalElement.addEventListener('hidden.bs.modal', function() {
            currentUserId = null;
        });
    }
});
