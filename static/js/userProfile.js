// Wait for the DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize Bootstrap modal
    const profileModal = new bootstrap.Modal(document.getElementById('userProfileModal'));
    
    // Function to format date strings
    function formatDate(dateString) {
        if (!dateString) return 'Not available';
        return new Date(dateString).toLocaleString();
    }
    
    // Function to safely update element text content
    function safeSetTextContent(elementId, text) {
        const element = document.getElementById(elementId);
        if (element) {
            element.textContent = text;
        } else {
            console.warn(`Element with id '${elementId}' not found`);
        }
    }

    // Function to safely update element src attribute
    function safeSetSrc(elementId, src) {
        const element = document.getElementById(elementId);
        if (element) {
            element.src = src;
        } else {
            console.warn(`Element with id '${elementId}' not found`);
        }
    }
    
    // Function to display user profile - making it globally accessible
    window.displayUserProfile = async function(userId) {
        try {
            console.log('Loading profile for user:', userId);
            
            // Show loading state
            safeSetTextContent('profileUsername', 'Loading...');
            safeSetTextContent('profileStatus', 'Please wait...');
            
            // Fetch user data
            const response = await fetch(`/api/user/by_id/${userId}`);
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const userData = await response.json();
            console.log('Profile data received:', userData);
            
            // Update modal content using safe update functions
            safeSetSrc('profileAvatar', userData.avatar || '/static/images/default-avatar.png');
            safeSetTextContent('profileUsername', userData.display_name || userData.username);
            safeSetTextContent('profileStatus', userData.status || 'No status set');
            safeSetTextContent('profileBio', userData.bio || 'No bio provided');
            safeSetTextContent('profileLocation', userData.location || 'Location not set');
            safeSetTextContent('profileJoinDate', formatDate(userData.created_at));
            safeSetTextContent('profileLastSeen', formatDate(userData.last_seen));
            
            // Show the modal
            profileModal.show();
        } catch (error) {
            console.error('Error loading user profile:', error);
            alert('Failed to load user profile. Please try again.');
        }
    };
    
    // Event delegation for user profile clicks
    document.body.addEventListener('click', function(event) {
        // Find closest ancestor with data-user-id attribute
        const userElement = event.target.closest('[data-user-id]');
        if (userElement) {
            event.preventDefault();
            const userId = userElement.dataset.userId;
            console.log('User element clicked, ID:', userId);
            window.displayUserProfile(userId);
        }
    });
    
    // Initialize message button handler
    const messageUserBtn = document.getElementById('messageUserBtn');
    if (messageUserBtn) {
        messageUserBtn.addEventListener('click', function() {
            const userElement = document.querySelector('[data-user-id].selected');
            if (userElement && typeof socket !== 'undefined') {
                socket.emit('start_direct_message', { target_user_id: userElement.dataset.userId });
                profileModal.hide();
            }
        });
    }
});
