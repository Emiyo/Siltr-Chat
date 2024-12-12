// Wait for the DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize the modal
    const profileModal = new bootstrap.Modal(document.getElementById('userProfileModal'), {
        keyboard: true
    });

    // Function to fetch and display user profile
    async function showUserProfile(userId) {
        try {
            console.log('Fetching profile for user:', userId);
            
            // Fetch user data
            const response = await fetch(`/api/user/by_id/${userId}`);
            console.log('API response status:', response.status);
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const userData = await response.json();
            console.log('Received user data:', userData);
            
            // Update modal content
            document.getElementById('profileAvatar').src = userData.avatar || '/static/images/default-avatar.png';
            document.getElementById('profileUsername').textContent = userData.display_name || userData.username;
            document.getElementById('profileStatus').textContent = userData.status || 'No status set';
            document.getElementById('profileBio').textContent = userData.bio || 'No bio provided';
            document.getElementById('profileLocation').textContent = userData.location || 'Location not set';
            document.getElementById('profileJoinDate').textContent = new Date(userData.created_at).toLocaleDateString();
            document.getElementById('profileLastSeen').textContent = userData.last_seen ? 
                new Date(userData.last_seen).toLocaleString() : 'Never';

            // Setup message button
            const messageBtn = document.getElementById('messageUserBtn');
            messageBtn.onclick = () => startDirectMessage(userData.id);
            
            // Show the modal
            profileModal.show();

        } catch (error) {
            console.error('Error loading user profile:', error);
            alert('Failed to load user profile: ' + error.message);
        }
    }

    // Function to start a direct message
    function startDirectMessage(userId) {
        if (typeof socket !== 'undefined') {
            socket.emit('start_direct_message', { target_user_id: userId });
            profileModal.hide();
        }
    }

    // Add click event listeners to user elements
    document.addEventListener('click', function(event) {
        const userElement = event.target.closest('[data-user-id]');
        if (userElement) {
            const userId = userElement.dataset.userId;
            if (userId) {
                event.preventDefault();
                console.log('User element clicked, userId:', userId);
                showUserProfile(userId);
            }
        }
    });

    // Export showUserProfile for global access if needed
    window.showUserProfile = showUserProfile;
});

// Update user presence indicator
function updateUserPresence(presenceState) {
    const indicator = document.getElementById('modalPresenceIndicator');
    if (indicator) {
        indicator.className = `presence-indicator ${presenceState}`;
    }
}

// Update user list with clickable profiles
function updateUserList(users) {
    const userList = document.getElementById('userList');
    if (!userList) return;

    userList.innerHTML = '';
    users.forEach(user => {
        const userItem = document.createElement('div');
        userItem.className = 'user-item';
        userItem.dataset.userId = user.id;
        userItem.innerHTML = `
            <div class="user-item-content">
                <img src="${user.avatar || '/static/images/default-avatar.png'}" 
                     alt="${user.username}'s avatar" 
                     class="user-avatar" />
                <div class="user-info">
                    <span class="username">${user.display_name || user.username}</span>
                    ${user.status ? `<span class="status">${user.status}</span>` : ''}
                </div>
            </div>
        `;
        userList.appendChild(userItem);
    });
}
