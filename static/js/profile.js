// Discord-like profile functionality
let socket;
let reconnectAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 3;

document.addEventListener('DOMContentLoaded', function() {
    // Initialize socket connection
    initializeSocket();
    
    // Fetch and display user profile in Discord style
    window.fetchAndDisplayUserProfile = async function(userId) {
        try {
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
            
            // Update modal content with Discord-style presence indicator
            const presenceClass = userData.presence_state || 'online';
            document.getElementById('modalUsername').innerHTML = `
                <div class="profile-header">
                    <span class="presence-indicator ${presenceClass}"></span>
                    <span class="username">${userData.display_name || userData.username}</span>
                    ${userData.roles && userData.roles.includes('admin') ? '<span class="badge admin-badge">Admin</span>' : ''}
                </div>
            `;

            // Set user status with emoji support
            document.getElementById('modalStatus').innerHTML = `
                <div class="status-container">
                    ${userData.status || 'Set a custom status'}
                </div>
            `;

            // Set avatar with presence ring
            const avatarContainer = document.getElementById('modalAvatarContainer');
            avatarContainer.innerHTML = `
                <div class="avatar-wrapper ${presenceClass}">
                    <img src="${userData.avatar || '/static/images/default-avatar.png'}" 
                         alt="Profile Avatar" 
                         class="profile-avatar">
                </div>
            `;

            // Member information
            document.getElementById('modalMemberInfo').innerHTML = `
                <div class="member-info">
                    <div class="member-since">
                        <h4>Discord Member Since</h4>
                        <span>${new Date(userData.created_at).toLocaleDateString()}</span>
                    </div>
                    ${userData.roles && userData.roles.length > 0 ? `
                        <div class="roles">
                            <h4>Roles</h4>
                            <div class="role-badges">
                                ${userData.roles.map(role => `<span class="role-badge">${role}</span>`).join('')}
                            </div>
                        </div>
                    ` : ''}
                </div>
            `;

            // Show modal
            modal.style.display = "block";
            
            console.log('Discord-style profile modal displayed for user:', userData.username);
        } catch (error) {
            console.error('Error fetching user profile:', error);
        }
    };

    // Close modal functionality
    const modals = document.querySelectorAll('.modal');
    modals.forEach(modal => {
        const closeBtn = modal.querySelector('.close');
        if (closeBtn) {
            closeBtn.onclick = () => modal.style.display = "none";
        }
        window.onclick = event => {
            if (event.target === modal) {
                modal.style.display = "none";
            }
        };
    });

    // Presence selector handler
    const presenceSelector = document.getElementById('presenceSelector');
    if (presenceSelector) {
        presenceSelector.addEventListener('change', event => {
    // Socket initialization and management
    function initializeSocket() {
        if (socket) {
            socket.disconnect();
        }
        
        socket = io({
            reconnection: true,
            reconnectionDelay: 1000,
            reconnectionDelayMax: 5000,
            reconnectionAttempts: MAX_RECONNECT_ATTEMPTS
        });

        socket.on('connect', () => {
            console.log('Socket connected successfully');
            reconnectAttempts = 0;
        });

        socket.on('disconnect', () => {
            console.log('Socket disconnected');
            if (reconnectAttempts < MAX_RECONNECT_ATTEMPTS) {
                reconnectAttempts++;
                setTimeout(initializeSocket, 1000 * reconnectAttempts);
            }
        });

        socket.on('connect_error', (error) => {
            console.error('Connection error:', error);
            if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
                console.error('Max reconnection attempts reached');
            }
        });
    }
            const newPresence = event.target.value;
            if (typeof socket !== 'undefined') {
                socket.emit('update_presence', { presence_state: newPresence });
            }
        });
    }
});
