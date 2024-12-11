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
        
        // Update modal content with presence indicator
        const presenceClass = userData.presence_state || 'online';
        document.getElementById('modalUsername').innerHTML = `
            <span class="presence-indicator ${presenceClass}"></span>
            ${userData.display_name || userData.username}
        `;
        document.getElementById('modalStatus').textContent = userData.status || 'No status set';
        document.getElementById('modalPresence').textContent = userData.presence_state || 'online';
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
        
        // Show modal
        modal.style.display = "block";
        
        console.log('Modal displayed for user:', userData.username);
    } catch (error) {
        console.error('Error fetching user profile:', error);
    }
};

document.addEventListener('DOMContentLoaded', function() {
    const modal = document.getElementById('userProfileModal');
    const closeBtn = modal.querySelector('.close');
    const profileButton = document.querySelector('a[href="/profile"]');
    
    // Handle profile button click
    if (profileButton) {
        profileButton.addEventListener('click', function(e) {
            e.preventDefault();
            fetchAndDisplayUserProfile('current');
        });
    }
    
    // Close modal when clicking the close button
    closeBtn.onclick = function() {
        modal.style.display = "none";
    }
    
    // Close modal when clicking outside
    window.onclick = function(event) {
        if (event.target == modal) {
            modal.style.display = "none";
        }
    }

    // Add click handlers to user list items
    function setupUserClickHandlers() {
        const userElements = document.querySelectorAll('.user-item');
        userElements.forEach(element => {
            element.addEventListener('click', function() {
                const userId = this.dataset.userId;
                fetchAndDisplayUserProfile(userId);
            });
        });
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

    // Setup initial handlers
    setupUserClickHandlers();

    // Setup WebSocket event listener for user list updates
    if (typeof socket !== 'undefined') {
        socket.on('user_list', function(data) {
            // After user list is updated, reattach click handlers
            setTimeout(setupUserClickHandlers, 100);
            
            // Update presence indicator if modal is open
            const modal = document.getElementById('userProfileModal');
            if (modal.style.display === "block") {
                const currentUserId = modal.dataset.currentUserId;
                const currentUser = data.users.find(u => u.id === currentUserId);
                if (currentUser) {
                    const indicator = document.getElementById('modalPresenceIndicator');
                    if (indicator) {
                        indicator.className = `presence-indicator ${currentUser.presence_state || 'online'}`;
                    }
                    const selector = document.getElementById('presenceSelector');
                    if (selector) {
                        selector.value = currentUser.presence_state || 'online';
                    }
                }
            }
        });
    }
});