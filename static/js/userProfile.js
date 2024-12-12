// Get actions from the global scope
const { setCurrentModal, setCurrentUserId, setUserData, setLoading, setError } = window.profileActions;

// Global profile display functionality
window.displayUserProfile = async function(userId) {
    store.dispatch(setLoading(true));
    try {
        currentUserId = userId;
        const endpoint = userId === 'current' ? '/api/user/profile' : `/api/user/by_id/${userId}`;
        const response = await fetch(endpoint);
        if (!response.ok) throw new Error('Failed to fetch user profile');
        const userData = await response.json();
        
        // Get modal
        const modal = document.getElementById('userProfileModal');
        if (!modal) {
            console.error('Modal element not found');
            return;
        }
        currentModal = modal;
        
        // Update avatar and presence
        const avatarSrc = userData.avatar || '/static/images/default-avatar.png';
        document.getElementById('modalUserAvatar').src = avatarSrc;
        updateUserPresence(userData.presence_state || 'online');

        // Update username and status
        document.getElementById('modalUsername').textContent = userData.display_name || userData.username;
        document.getElementById('modalStatus').textContent = userData.status || 'No status set';

        // Update bio and location
        document.getElementById('modalBio').textContent = userData.bio || 'No bio provided';
        document.getElementById('modalLocation').textContent = userData.location ? `📍 ${userData.location}` : '';

        // Update member info
        document.getElementById('modalJoinDate').textContent = `Joined: ${new Date(userData.created_at).toLocaleDateString()}`;
        document.getElementById('modalLastSeen').textContent = userData.last_seen ? 
            `Last seen: ${new Date(userData.last_seen).toLocaleString()}` : 'Last seen: Never';

        // Update roles
        const rolesDiv = document.getElementById('modalRoles');
        rolesDiv.innerHTML = userData.roles ? 
            userData.roles.map(role => `<span class="role-badge">${role}</span>`).join('') : '';

        // Configure direct message button
        const messageBtn = document.getElementById('startDirectMessageBtn');
        if (userId === 'current') {
            messageBtn.style.display = 'none';
        } else {
            messageBtn.style.display = 'block';
            messageBtn.onclick = () => startDirectMessage(userId);
        }

        // Show modal
        modal.style.display = "block";
    } catch (error) {
        console.error('Error fetching user profile:', error);
    }
};

// Initialize event handlers when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    const modal = document.getElementById('userProfileModal');
    const closeBtn = modal.querySelector('.close');

    // Initialize Socket.IO event handlers for real-time updates
    if (typeof io !== 'undefined') {
        const socket = io({
            transports: ['websocket', 'polling'],
            upgrade: true
        });

        socket.on('user_list', function(data) {
            if (currentUserId && modal.style.display === "block") {
                const currentUser = data.users.find(u => u.id === currentUserId);
                if (currentUser) {
                    updateUserPresence(currentUser.presence_state || 'online');
                }
            }
            updateUserList(data.users);
        });
    }
        try {
            currentUserId = userId;
            const endpoint = userId === 'current' ? '/api/user/profile' : `/api/user/by_id/${userId}`;
            const response = await fetch(endpoint);
            if (!response.ok) throw new Error('Failed to fetch user profile');
            const userData = await response.json();
            
            // Update avatar and presence
            const avatarSrc = userData.avatar || '/static/images/default-avatar.png';
            document.getElementById('modalUserAvatar').src = avatarSrc;
            updateUserPresence(userData.presence_state || 'online');

            // Update username and status
            document.getElementById('modalUsername').textContent = userData.display_name || userData.username;
            document.getElementById('modalStatus').textContent = userData.status || 'No status set';

            // Update bio and location
            document.getElementById('modalBio').textContent = userData.bio || 'No bio provided';
            document.getElementById('modalLocation').textContent = userData.location ? `📍 ${userData.location}` : '';

            // Update member info
            document.getElementById('modalJoinDate').textContent = `Joined: ${new Date(userData.created_at).toLocaleDateString()}`;
            document.getElementById('modalLastSeen').textContent = userData.last_seen ? 
                `Last seen: ${new Date(userData.last_seen).toLocaleString()}` : 'Last seen: Never';

            // Update roles
            const rolesDiv = document.getElementById('modalRoles');
            rolesDiv.innerHTML = userData.roles ? 
                userData.roles.map(role => `<span class="role-badge">${role}</span>`).join('') : '';

            // Configure direct message button
            const messageBtn = document.getElementById('startDirectMessageBtn');
            if (userId === 'current') {
                messageBtn.style.display = 'none';
            } else {
                messageBtn.style.display = 'block';
                messageBtn.onclick = () => startDirectMessage(userId);
            }

            // Show modal
            modal.style.display = "block";
        } catch (error) {
            console.error('Error fetching user profile:', error);
        }
    };

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
            userItem.onclick = () => displayUserProfile(user.id);
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

    // Direct message functionality
    window.startDirectMessage = function(userId) {
        if (typeof socket !== 'undefined') {
            socket.emit('start_direct_message', { target_user_id: userId });
            modal.style.display = "none";
        } else {
            console.error('Socket connection not available');
        }
    };

    // Modal close functionality
    if (closeBtn) {
        closeBtn.onclick = () => modal.style.display = "none";
    }

    // Close modal when clicking outside
    window.onclick = event => {
        if (event.target === modal) {
            modal.style.display = "none";
        }
    };
});
