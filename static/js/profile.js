// Discord-like profile functionality
let socket;
let reconnectAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 3;

document.addEventListener('DOMContentLoaded', function() {
    const presenceSelector = document.getElementById('presenceSelector');
    
    if (presenceSelector) {
        presenceSelector.addEventListener('change', event => {
            const newPresence = event.target.value;
            if (socket && socket.connected) {
                socket.emit('update_presence', { presence_state: newPresence });
            }
        });
    }

    function initializeSocket() {
        if (!socket) {
            socket = io({
                transports: ['websocket', 'polling'],
                upgrade: true,
                reconnection: true,
                reconnectionAttempts: 5,
                reconnectionDelay: 1000,
                reconnectionDelayMax: 5000,
                timeout: 20000,
                query: { timestamp: Date.now() }
            });

            socket.on('connect_error', (error) => {
                console.error('Connection error:', error);
                reconnectAttempts++;
                if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
                    console.error('Max reconnection attempts reached');
                }
            });
            
            socket.on('connect', () => {
                console.log('Socket connected successfully');
                reconnectAttempts = 0;
                socket.emit('get_categories');
                socket.emit('get_user_list');
            });

            socket.on('disconnect', () => {
                console.log('Socket disconnected');
            });

            socket.on('error', (data) => {
                console.error('Socket error:', data);
            });

            socket.on('user_connected', (userData) => {
                console.log('User connected:', userData);
            });

            socket.on('categories_list', (data) => {
                console.log('Received categories:', data);
                if (data.categories) {
                    updateCategories(data.categories);
                }
            });

            socket.on('user_list', (data) => {
                console.log('Received user list:', data);
                if (data.users) {
                    updateUserList(data.users);
                }
            });
        }
    }

    function updateCategories(categories) {
        const categoryList = document.getElementById('categoryList');
        if (!categoryList) return;

        categoryList.innerHTML = '';
        categories.forEach(category => {
            const categoryItem = document.createElement('div');
            categoryItem.className = 'category-item';
            categoryItem.innerHTML = `
                <div class="category-header">
                    <span>${category.name}</span>
                </div>
                ${category.channels ? `
                    <div class="channel-list">
                        ${category.channels.map(channel => `
                            <div class="channel-item ${channel.is_private ? 'channel-private' : ''}">
                                <span>#${channel.name}</span>
                            </div>
                        `).join('')}
                    </div>
                ` : ''}
            `;
            categoryList.appendChild(categoryItem);
        });
    }

    function updateUserList(users) {
        const userList = document.getElementById('userList');
        if (!userList) return;

        userList.innerHTML = '';
        users.forEach(user => {
            const userItem = document.createElement('div');
            userItem.className = 'user-item';
            userItem.innerHTML = `
                <span class="presence-indicator ${user.presence_state || 'offline'}"></span>
                <span class="username">${user.username}</span>
                ${user.status ? `<span class="status">${user.status}</span>` : ''}
            `;
            userList.appendChild(userItem);
        });
    }

    // Initialize socket when the page loads
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
});