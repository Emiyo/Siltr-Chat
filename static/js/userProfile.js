// Wait for the DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize the modal
    const profileModal = new bootstrap.Modal(document.getElementById('userProfileModal'));
    
    // Function to format date
    function formatDate(dateString) {
        return dateString ? new Date(dateString).toLocaleString() : 'Not available';
    }

    // Function to fetch and display user profile
    async function showUserProfile(userId) {
        try {
            // Show loading state
            document.getElementById('profileUsername').textContent = 'Loading...';
            
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

            // Setup message button
            const messageBtn = document.getElementById('messageUserBtn');
            messageBtn.onclick = () => {
                if (typeof socket !== 'undefined') {
                    socket.emit('start_direct_message', { target_user_id: userId });
                    profileModal.hide();
                }
            };

            // Show the modal
            profileModal.show();
        } catch (error) {
            console.error('Error loading user profile:', error);
            alert('Failed to load user profile. Please try again.');
        }
    }

    // Add click event listeners to user elements
    document.addEventListener('click', function(event) {
        const userElement = event.target.closest('[data-user-id]');
        if (userElement) {
            const userId = userElement.dataset.userId;
            if (userId) {
                event.preventDefault();
                console.log('Opening profile for user:', userId);
                showUserProfile(userId);
            }
        }
    });

    // Make showUserProfile available globally if needed for legacy code
    window.showUserProfile = showUserProfile;
});
