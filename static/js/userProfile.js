// Wait for the DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize Bootstrap modal
    const profileModal = new bootstrap.Modal(document.getElementById('userProfileModal'));
    
    // Function to format date strings
    function formatDate(dateString) {
        if (!dateString) return 'Not available';
        return new Date(dateString).toLocaleString();
    }
    
    // Function to handle profile data loading and display
    async function loadUserProfile(userId) {
        try {
            console.log('Loading profile for user:', userId);
            
            // Show loading state
            document.getElementById('profileUsername').textContent = 'Loading...';
            document.getElementById('profileStatus').textContent = 'Please wait...';
            
            // Fetch user data
            const response = await fetch(`/api/user/by_id/${userId}`);
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const userData = await response.json();
            console.log('Profile data received:', userData);
            
            // Update modal content
            document.getElementById('profileAvatar').src = userData.avatar || '/static/images/default-avatar.png';
            document.getElementById('profileUsername').textContent = userData.display_name || userData.username;
            document.getElementById('profileStatus').textContent = userData.status || 'No status set';
            document.getElementById('profileBio').textContent = userData.bio || 'No bio provided';
            document.getElementById('profileLocation').textContent = userData.location || 'Location not set';
            document.getElementById('profileJoinDate').textContent = formatDate(userData.created_at);
            document.getElementById('profileLastSeen').textContent = formatDate(userData.last_seen);
            
            // Show the modal
            profileModal.show();
        } catch (error) {
            console.error('Error loading user profile:', error);
            alert('Failed to load user profile. Please try again.');
        }
    }
    
    // Event delegation for user profile clicks
    document.body.addEventListener('click', function(event) {
        // Find closest ancestor with data-user-id attribute
        const userElement = event.target.closest('[data-user-id]');
        if (userElement) {
            event.preventDefault();
            const userId = userElement.dataset.userId;
            console.log('User element clicked, ID:', userId);
            loadUserProfile(userId);
        }
    });
    
    // Initialize message button handler
    document.getElementById('messageUserBtn').addEventListener('click', function() {
        const userElement = document.querySelector('[data-user-id].selected');
        if (userElement && typeof socket !== 'undefined') {
            socket.emit('start_direct_message', { target_user_id: userElement.dataset.userId });
            profileModal.hide();
        }
    });
});
