// Initialize profile display functionality
function initializeProfileHandlers() {
    if (!window.store || !window.profileActions) {
        console.error('Redux store or actions not initialized');
        return;
    }
    
    const { clearProfile } = window.profileActions;
    const store = window.store;
    
    // Initialize Bootstrap modal once
    const modalElement = document.getElementById('userProfileModal');
    const profileModal = new bootstrap.Modal(modalElement, {
        keyboard: true,
        backdrop: true,
        focus: true
    });
    
    // Subscribe to store changes
    store.subscribe(() => {
        const state = store.getState().profile;
        
        if (state.isModalOpen && state.userData) {
            // Update UI with user data
            updateProfileUI(state.userData);
            profileModal.show();
        } else {
            profileModal.hide();
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

    // Setup close button handler
    const closeBtn = modalElement.querySelector('.close');
    if (closeBtn) {
        closeBtn.onclick = () => {
            store.dispatch(clearProfile());
        };
    }

    // Handle Bootstrap modal events
    modalElement.addEventListener('hidden.bs.modal', () => {
        store.dispatch(clearProfile());
    });

    modalElement.addEventListener('show.bs.modal', () => {
        console.log('Modal is about to show');
    });

    modalElement.addEventListener('shown.bs.modal', () => {
        console.log('Modal is now visible');
    });

    // Use event delegation for all profile-related clicks
    document.addEventListener('click', function(e) {
        // Handle both profile buttons and user items
        const profileElement = e.target.closest('.profile-btn, .user-item');
        if (profileElement) {
            e.preventDefault();
            e.stopPropagation();
            
            // Get userId from either data attribute or user-item
            let userId;
            if (profileElement.classList.contains('profile-btn')) {
                userId = profileElement.getAttribute('data-user-id');
            } else {
                userId = profileElement.getAttribute('data-user-id');
            }

            console.log('Profile click detected:', { userId, element: profileElement });

            if (userId && window.store && window.displayUserProfile) {
                window.store.dispatch(window.displayUserProfile(userId));
            } else {
                console.error('Missing required data:', {
                    userId,
                    store: !!window.store,
                    displayUserProfile: !!window.displayUserProfile
                });
            }
        }
    });

    // Update any existing profile buttons
    const updateProfileButtons = () => {
        const profileButtons = document.querySelectorAll('.profile-btn, .user-item');
        profileButtons.forEach(btn => {
            if (!btn.hasAttribute('data-user-id')) {
                const userId = btn.getAttribute('onclick')?.match(/['"]([^'"]+)['"]/))?.[1];
                if (userId) {
                    btn.setAttribute('data-user-id', userId);
                    btn.removeAttribute('onclick');
                }
            }
        });
    };

    // Initial update
    updateProfileButtons();

    // Update buttons when user list changes
    const userList = document.getElementById('userList');
    if (userList) {
        const observer = new MutationObserver(updateProfileButtons);
        observer.observe(userList, { childList: true, subtree: true });
    }
}

// Initialize when DOM and Redux are ready
document.addEventListener('DOMContentLoaded', function() {
    let storeInitAttempts = 0;
    const maxAttempts = 50; // 5 seconds total
    
    const checkStoreAndInitialize = () => {
        if (window.store && window.profileActions && typeof bootstrap !== 'undefined') {
            console.log('Store, actions, and Bootstrap initialized');
            initializeProfileHandlers();
            return true;
        }
        return false;
    };

    // Try immediate initialization
    if (!checkStoreAndInitialize()) {
        // Set up polling if immediate init fails
        const checkStoreInterval = setInterval(() => {
            storeInitAttempts++;
            
            if (checkStoreAndInitialize()) {
                clearInterval(checkStoreInterval);
            } else if (storeInitAttempts >= maxAttempts) {
                clearInterval(checkStoreInterval);
                console.error('Store initialization timed out. Missing:', {
                    store: !window.store,
                    actions: !window.profileActions,
                    bootstrap: typeof bootstrap === 'undefined'
                });
            }
        }, 100);
    }
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