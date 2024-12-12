// Initialize profile display functionality
function initializeProfileHandlers() {
    if (!window.store || !window.profileActions) {
        console.error('Redux store or actions not initialized');
        return;
    }
    
    const { openModal, closeModal, setUserData, clearProfile } = window.profileActions;
    const store = window.store;
    
    // Subscribe to store changes
    store.subscribe(() => {
        const state = store.getState().profile;
        const modal = document.getElementById('userProfileModal');
        
        if (state.isModalOpen && state.userData) {
            // Update UI with user data
            updateProfileUI(state.userData);
            modal.style.display = "block";
        } else {
            modal.style.display = "none";
        }
    });

    // Update UI helper function
    function updateProfileUI(userData) {
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
        if (userData.id === 'current') {
            messageBtn.style.display = 'none';
        } else {
            messageBtn.style.display = 'block';
            messageBtn.onclick = () => startDirectMessage(userData.id);
        }
    }

    // Update user presence indicator
    function updateUserPresence(presenceState) {
        const indicator = document.getElementById('modalPresenceIndicator');
        if (indicator) {
            indicator.className = `presence-indicator ${presenceState}`;
        }
    }

    // Setup modal close handlers
    const modal = document.getElementById('userProfileModal');
    const closeBtn = modal.querySelector('.close');

    if (closeBtn) {
        closeBtn.onclick = () => {
            store.dispatch(clearProfile());
        };
    }

    // Close modal when clicking outside
    window.onclick = function(event) {
        if (event.target === modal) {
            store.dispatch(clearProfile());
        }
    };

    // Override the click handlers to use Redux
    const userElements = document.querySelectorAll('[onclick*="displayUserProfile"]');
    userElements.forEach(element => {
        const userId = element.getAttribute('onclick').match(/'([^']+)'/)[1];
        element.onclick = (e) => {
            e.preventDefault();
            store.dispatch(window.displayUserProfile(userId));
        };
    });
}

// Initialize when DOM and Redux are ready
document.addEventListener('DOMContentLoaded', function() {
    // Wait for Redux store to be initialized
    const checkStoreInterval = setInterval(() => {
        if (window.store && window.profileActions) {
            clearInterval(checkStoreInterval);
            initializeProfileHandlers();
        }
    }, 100);

    // Safety timeout after 5 seconds
    setTimeout(() => {
        clearInterval(checkStoreInterval);
        if (!window.store || !window.profileActions) {
            console.error('Redux store initialization timed out');
        }
    }, 5000);
    const modal = document.getElementById('userProfileModal');
    const closeBtn = modal.querySelector('.close');

    // Initialize Socket.IO event handlers for real-time updates
    if (typeof io !== 'undefined') {
        const socket = io({
            transports: ['websocket', 'polling'],
            upgrade: true
        });

        socket.on('user_list', function(data) {
            const state = store.getState().profile;
            if (state.currentUserId && state.currentModal && state.currentModal.style.display === "block") {
                const currentUser = data.users.find(u => u.id === state.currentUserId);
                if (currentUser) {
                    updateUserPresence(currentUser.presence_state || 'online');
                }
            }
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
            userItem.onclick = () => window.displayUserProfile(user.id);
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
        closeBtn.onclick = () => {
            modal.style.display = "none";
            store.dispatch(clearProfile());
        };
    }

    // Close modal when clicking outside
    window.onclick = function(event) {
        if (event.target === modal) {
            modal.style.display = "none";
            store.dispatch(clearProfile());
        }
    };
});