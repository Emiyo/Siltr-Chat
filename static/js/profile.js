// Theme Management
document.addEventListener('DOMContentLoaded', function() {
    const themeSelect = document.getElementById('theme');
    const customThemeOptions = document.querySelector('.custom-theme-options');
    const bannerColorPicker = document.getElementById('banner_color');
    const accentColorPicker = document.getElementById('accent_color');
    const preview = document.querySelector('.theme-preview');

    // Theme Selection Handler
    if (themeSelect) {
        themeSelect.addEventListener('change', function(e) {
            const selectedTheme = e.target.value;
            const root = document.documentElement;
            
            // Apply theme with smooth transition
            root.style.transition = 'none';
            root.setAttribute('data-theme', selectedTheme);
            
            // Force reflow for smooth transition
            void root.offsetWidth;
            root.style.transition = 'background-color 0.3s ease, color 0.3s ease, border-color 0.3s ease';
            
            // Update preview container with smooth transition
            if (preview) {
                preview.classList.add('transitioning');
                setTimeout(() => {
                    // Update theme-specific styles
                    preview.classList.remove('transitioning');
                }, 300);
            }
            
            // Toggle custom theme options with enhanced animation
            if (customThemeOptions) {
                if (selectedTheme === 'custom') {
                    customThemeOptions.style.display = 'block';
                    customThemeOptions.style.transform = 'translateY(-10px)';
                    setTimeout(() => {
                        customThemeOptions.style.opacity = '1';
                        customThemeOptions.style.transform = 'translateY(0)';
                    }, 10);
                } else {
                    customThemeOptions.style.opacity = '0';
                    customThemeOptions.style.transform = 'translateY(-10px)';
                    setTimeout(() => {
                        customThemeOptions.style.display = 'none';
                    }, 300);
                }
            }
            
            // Save theme preference
            fetch('/update_theme', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ theme: selectedTheme })
            });
        });
    }

    // Color Picker Handlers
    if (bannerColorPicker) {
        bannerColorPicker.addEventListener('input', function(e) {
            const banner = document.querySelector('.profile-banner');
            if (banner) {
                banner.style.backgroundColor = e.target.value;
            }
        });
    }

    if (accentColorPicker) {
        accentColorPicker.addEventListener('input', function(e) {
            const color = e.target.value;
            const root = document.documentElement;
            
            // Update CSS variables with new accent color
            root.style.setProperty('--primary-color', color);
            root.style.setProperty('--interactive-active', color);
            
            // Create transparent versions for hover and active states
            const rgba = hexToRGBA(color, 0.1);
            const rgbaHover = hexToRGBA(color, 0.15);
            root.style.setProperty('--primary-transparent', rgba);
            root.style.setProperty('--primary-transparent-hover', rgbaHover);
            
            // Update preview elements
            if (preview) {
                preview.classList.add('transitioning');
                setTimeout(() => {
                    const previewMessages = preview.querySelectorAll('.preview-message');
                    previewMessages.forEach(msg => {
                        if (msg.classList.contains('preview-own')) {
                            msg.style.borderLeft = `4px solid ${color}`;
                            msg.style.backgroundColor = rgba;
                        }
                    });
                    
                    // Update preview input
                    const previewInput = preview.querySelector('.preview-input');
                    if (previewInput) {
                        previewInput.style.borderColor = color;
                    }
                    
                    preview.classList.remove('transitioning');
                }, 150);
            }

            // Save accent color preference
            fetch('/update_theme', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ accent_color: color })
            });
        });
    }

    // Helper function to convert hex to rgba
    function hexToRGBA(hex, alpha) {
        const r = parseInt(hex.slice(1, 3), 16);
        const g = parseInt(hex.slice(3, 5), 16);
        const b = parseInt(hex.slice(5, 7), 16);
        return `rgba(${r}, ${g}, ${b}, ${alpha})`;
    }

    // Initialize theme and accent color from user preferences
    function initializeTheme() {
        if (themeSelect) {
            const savedTheme = themeSelect.value;
            const root = document.documentElement;
            
            // Apply saved theme
            root.style.transition = 'none';
            root.setAttribute('data-theme', savedTheme);
            void root.offsetWidth;
            root.style.transition = 'background-color 0.3s ease, color 0.3s ease, border-color 0.3s ease';
            
            // Initialize custom theme options if needed
            if (customThemeOptions) {
                if (savedTheme === 'custom') {
                    customThemeOptions.style.display = 'block';
                    customThemeOptions.style.opacity = '1';
                    
                    // Apply saved accent color if available
                    if (accentColorPicker && accentColorPicker.value) {
                        const color = accentColorPicker.value;
                        root.style.setProperty('--primary-color', color);
                        root.style.setProperty('--interactive-active', color);
                        
                        const rgba = hexToRGBA(color, 0.1);
                        const rgbaHover = hexToRGBA(color, 0.15);
                        root.style.setProperty('--primary-transparent', rgba);
                        root.style.setProperty('--primary-transparent-hover', rgbaHover);
                    }
                } else {
                    customThemeOptions.style.display = 'none';
                    customThemeOptions.style.opacity = '0';
                }
            }
            
            console.log('Theme initialized:', savedTheme);
        }
    }
    
    // Call initialization on page load
    initializeTheme();
});
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

    // Status input handling
    const statusInput = document.getElementById('status');

    // Status update handler
    if (statusInput) {
        let updateTimeout;
        statusInput.addEventListener('input', () => {
            clearTimeout(updateTimeout);
            updateTimeout = setTimeout(() => {
                if (socket && socket.connected) {
                    socket.emit('update_status', {
                        status: statusInput.value,
                        status_emoji: statusEmojiInput.value
                    });
                }
            }, 500); // Debounce status updates
        });
    }

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