// Define fetchAndDisplayUserProfile in the global scope first
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
        
        // Store user ID for direct messaging
        modal.dataset.userId = userData.id;
        
        // Update modal content
        document.getElementById('modalUsername').innerHTML = `
            <div class="profile-header">
                <span class="username">${userData.display_name || userData.username}</span>
                ${userData.roles && userData.roles.includes('admin') ? '<span class="badge admin-badge">Admin</span>' : ''}
            </div>
        `;
        document.getElementById('modalStatus').textContent = userData.status || 'No status set';
        document.getElementById('modalBio').textContent = userData.bio || 'No bio provided';
        document.getElementById('modalLocation').textContent = userData.location ? `📍 ${userData.location}` : '';
        
        // Set avatar
        const avatarElement = document.getElementById('modalUserAvatar');
        avatarElement.src = userData.avatar || '/static/images/default-avatar.png';
        
        // Update contact information
        const contactDiv = document.getElementById('modalContact');
        contactDiv.innerHTML = '';
        if (userData.contact_info && userData.contact_info.email_visibility === 'public') {
            contactDiv.innerHTML += `<p>✉️ ${userData.email}</p>`;
        }
        if (userData.contact_info && userData.contact_info.social_links) {
            const socialLinks = document.createElement('div');
            socialLinks.className = 'social-links';
            const links = userData.contact_info.social_links;
            if (links.github) socialLinks.innerHTML += `<a href="${links.github}" target="_blank">GitHub</a>`;
            if (links.linkedin) socialLinks.innerHTML += `<a href="${links.linkedin}" target="_blank">LinkedIn</a>`;
            if (links.twitter) socialLinks.innerHTML += `<a href="${links.twitter}" target="_blank">Twitter</a>`;
            if (socialLinks.children.length > 0) contactDiv.appendChild(socialLinks);
        }
        
        // Update member information
        document.getElementById('modalJoinDate').textContent = `Joined: ${new Date(userData.created_at).toLocaleDateString()}`;
        document.getElementById('modalLastSeen').textContent = userData.last_seen ? 
            `Last seen: ${new Date(userData.last_seen).toLocaleString()}` : 'Last seen: Never';
        
        // Update roles
        const rolesDiv = document.getElementById('modalRoles');
        rolesDiv.innerHTML = userData.roles ? 
            userData.roles.map(role => `<span class="role-badge">${role}</span>`).join('') : '';
        
        // Add direct message button if not viewing own profile
        const userActionsDiv = modal.querySelector('.user-actions');
        if (userId !== 'current') {
            userActionsDiv.innerHTML = `
                <button class="btn btn-terminal" onclick="startDirectMessage('${userData.id}')">Message</button>
            `;
        } else {
            userActionsDiv.innerHTML = ''; // Clear actions for own profile
        }
        
        // Show modal
        modal.style.display = "block";
        
        console.log('Modal displayed for user:', userData.username);
    } catch (error) {
        console.error('Error fetching user profile:', error);
    }
};

// Function to start a direct message
window.startDirectMessage = function(userId) {
    if (typeof socket !== 'undefined') {
        socket.emit('start_direct_message', { target_user_id: userId });
        const modal = document.getElementById('userProfileModal');
        if (modal) {
            modal.style.display = "none";
        }
    } else {
        console.error('Socket connection not available');
    }
};

// Modal UI operations
document.addEventListener('DOMContentLoaded', function() {
    const modal = document.getElementById('userProfileModal');
    const closeBtn = modal.querySelector('.close');
    const profileButton = document.querySelector('a[href="/profile"]');
    
    // Handle profile button click
    if (profileButton) {
        profileButton.addEventListener('click', function(e) {
            e.preventDefault();
            if (typeof window.fetchAndDisplayUserProfile === 'function') {
                window.fetchAndDisplayUserProfile('current');
            } else {
                console.error('Profile functionality not loaded');
            }
        });
    }
    
    // Close modal when clicking the close button
    if (closeBtn) {
        closeBtn.onclick = function() {
            modal.style.display = "none";
        }
    }
    
    // Close modal when clicking outside
    window.onclick = function(event) {
        if (event.target == modal) {
            modal.style.display = "none";
        }
    }

    // Setup presence selector handler
    const presenceSelector = document.getElementById('presenceSelector');
    if (presenceSelector) {
        presenceSelector.addEventListener('change', function(event) {
            const newPresence = event.target.value;
            if (typeof socket !== 'undefined') {
                socket.emit('update_presence', { presence_state: newPresence });
            }
        });
    }

    // Setup WebSocket event listener for user list updates
    if (typeof socket !== 'undefined') {
        socket.on('user_list', function(data) {
            // Update presence indicator if modal is open
            if (modal.style.display === "block") {
                const currentUserId = modal.dataset.currentUserId;
                const currentUser = data.users.find(u => u.id === currentUserId);
                if (currentUser) {
                    const indicator = document.getElementById('modalPresenceIndicator');
                    if (indicator) {
                        indicator.className = `presence-indicator ${currentUser.presence_state || 'online'}`;
                    }
                    if (presenceSelector) {
                        presenceSelector.value = currentUser.presence_state || 'online';
                    }
                }
            }
        });
    }
});