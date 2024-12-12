// Wait for the DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize the modal
    const profileModal = new bootstrap.Modal(document.getElementById('userProfileModal'), {
        keyboard: true
    });

    // Function to fetch and display user profile
    async function showUserProfile(userId) {
        try {
            // Fetch user data
            const response = await fetch(`/api/user/by_id/${userId}`);
            if (!response.ok) {
                throw new Error('Failed to fetch user profile');
            }

            const userData = await response.json();
            
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
            alert('Failed to load user profile');
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
                showUserProfile(userId);
            }
        }
    });

    // Export showUserProfile for global access if needed
    window.showUserProfile = showUserProfile;
});

// Initialize Socket.IO event handlers for real-time updates
if (typeof io !== 'undefined') {
    const socket = io({
        transports: ['websocket', 'polling'],
        upgrade: true
    });

    socket.on('user_list', function(data) {
        updateUserList(data.users);
    });
}

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
        userItem.dataset.userId = user.id; //added data-user-id
        userItem.innerHTML = `
            <div class="user-item-content">
                <span class="presence-indicator ${user.presence_state || 'offline'}"></span>
                <span class="username">${user.display_name || user.username}</span>
                ${user.status ? `<span class="status">${user.status}</span>` : ''}
            </div>
        `;
        userList.appendChild(userItem);
    });
}