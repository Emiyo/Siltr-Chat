// Helper functions defined first
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

function safeSetTextContent(elementId, text) {
    const element = document.getElementById(elementId);
    if (element) {
        element.textContent = text || '';
    }
}

function safeSetSrc(elementId, src) {
    const element = document.getElementById(elementId);
    if (element) {
        element.src = src || '/static/images/default-avatar.png';
    }
}

function updateThemePreview(color) {
    document.documentElement.style.setProperty('--primary-color', color);
    document.documentElement.style.setProperty('--primary-transparent', `${color}1A`);
    document.documentElement.style.setProperty('--primary-transparent-hover', `${color}26`);
}

function updateProfileBanner(color) {
    const banner = document.getElementById('modalBanner');
    if (banner) {
        banner.style.backgroundColor = color;
    }
}

// Global variables
let profileModal = null;
let currentUserId = null;
let colorPicker = null;

// Define displayUserProfile as a global function
window.displayUserProfile = async function(userId) {
    try {
        if (!userId) {
            console.error('No user ID provided');
            return;
        }
        
        currentUserId = userId;
        console.log('Loading profile for user:', userId);
        
        const content = document.querySelector('.profile-content');
        if (content) {
            content.innerHTML = '<div class="loading-spinner"></div><div class="text-center mt-3">Loading profile...</div>';
        }
        
        try {
            const response = await fetch(`/api/user/by_id/${userId}`);
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const userData = await response.json();
            console.log('Profile data received:', userData);

            if (!userData || typeof userData !== 'object') {
                throw new Error('Invalid user data received');
            }
        
            // Update modal content with proper error handling
            const defaultAvatar = '/static/images/default-avatar.png';
            const avatar = document.getElementById('modalUserAvatar');
            if (avatar) {
                avatar.src = userData.avatar || defaultAvatar;
                avatar.onerror = () => { avatar.src = defaultAvatar; };
            }

            safeSetTextContent('modalUsername', userData.display_name || userData.username);
            safeSetTextContent('modalStatus', userData.status || 'No status set');
            safeSetTextContent('modalBio', userData.bio || 'No bio provided');
            safeSetTextContent('modalLocation', userData.location || 'Location not set');
            safeSetTextContent('modalJoinDate', formatDate(userData.created_at));
            safeSetTextContent('modalLastSeen', formatDate(userData.last_seen));
            
            // Update theme color and preview
            const picker = document.getElementById('accentColorPicker');
            if (picker && userData.accent_color) {
                picker.value = userData.accent_color;
                updateThemePreview(userData.accent_color);
                updateProfileBanner(userData.accent_color);
            }

            // Add loading complete class to enable animations
            if (content) {
                content.classList.add('loaded');
            }
            
            // Show the modal
            if (profileModal) {
                profileModal.show();
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
    } catch (error) {
        console.error('Error in displayUserProfile:', error);
    }
};

// Wait for the DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize Bootstrap modal
    profileModal = new bootstrap.Modal(document.getElementById('userProfileModal'));
    
    // Initialize color picker
    colorPicker = document.getElementById('accentColorPicker');
    if (colorPicker) {
        colorPicker.addEventListener('input', function(e) {
            const color = e.target.value;
            updateThemePreview(color);
            updateProfileBanner(color);
        });
    }
    
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
