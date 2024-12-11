// Enhanced Profile functionality with Discord-like features
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
        
        // Set banner image and accent color
        const profileHeader = document.querySelector('.profile-header');
        if (userData.banner) {
            profileHeader.style.backgroundImage = `url(${userData.banner})`;
            profileHeader.classList.add('has-banner');
        } else {
            profileHeader.style.backgroundImage = 'none';
            profileHeader.classList.remove('has-banner');
        }
        
        // Apply accent color to relevant elements
        document.documentElement.style.setProperty('--user-accent-color', userData.accent_color || '#5865F2');
        
        // Update username and status with emoji
        const displayName = userData.display_name || userData.username;
        document.getElementById('modalUsername').innerHTML = `
            <span class="presence-indicator ${userData.presence_state || 'online'}"></span>
            ${displayName}
        `;
        
        // Update status with emoji support
        const statusText = userData.status || 'No status set';
        const statusEmoji = userData.status_emoji || '';
        document.getElementById('modalStatus').innerHTML = `
            <span class="status-emoji">${statusEmoji}</span>
            <span class="status-text">${statusText}</span>
        `;
        
        // Update rich presence details
        const presenceDetails = userData.presence_details || {};
        const presenceElement = document.getElementById('modalPresence');
        if (presenceDetails.activity) {
            presenceElement.innerHTML = `
                <div class="rich-presence">
                    ${presenceDetails.activity_type ? `<span class="activity-type">${presenceDetails.activity_type}</span>` : ''}
                    <span class="activity-name">${presenceDetails.activity}</span>
                    ${presenceDetails.details ? `<div class="activity-details">${presenceDetails.details}</div>` : ''}
                    ${presenceDetails.state ? `<div class="activity-state">${presenceDetails.state}</div>` : ''}
                </div>
            `;
        } else {
            presenceElement.textContent = userData.presence_state || 'online';
        }
        
        // Set avatar with border color based on presence
        const avatarElement = document.getElementById('modalUserAvatar');
        avatarElement.src = userData.avatar || '/static/images/default-avatar.png';
        avatarElement.className = `modal-avatar presence-${userData.presence_state || 'online'}`;
        
        // Update bio
        document.getElementById('modalBio').textContent = userData.bio || 'No bio provided';
        
        // Update member information with Discord-style formatting
        const joinDate = new Date(userData.created_at);
        const lastSeen = userData.last_seen ? new Date(userData.last_seen) : null;
        document.getElementById('modalJoinDate').innerHTML = `
            <span class="info-label">Joined Discord</span>
            <span class="info-value">${joinDate.toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' })}</span>
        `;
        if (lastSeen) {
            document.getElementById('modalLastSeen').innerHTML = `
                <span class="info-label">Last seen</span>
                <span class="info-value">${lastSeen.toLocaleString()}</span>
            `;
        }
        
        // Update roles with enhanced styling
        const rolesDiv = document.getElementById('modalRoles');
        if (userData.roles && userData.roles.length > 0) {
            rolesDiv.innerHTML = `
                <div class="roles-header">Roles</div>
                <div class="roles-list">
                    ${userData.roles.map(role => `
                        <span class="role-badge" style="background-color: ${role.color || '#99AAB5'}">
                            ${role.icon ? `<span class="role-icon">${role.icon}</span>` : ''}
                            ${role.name}
                        </span>
                    `).join('')}
                </div>
            `;
        } else {
            rolesDiv.innerHTML = '';
        }
        
        // Show modal
        modal.style.display = "block";
        
        console.log('Enhanced profile modal displayed for user:', userData.username);
    } catch (error) {
        console.error('Error fetching user profile:', error);
    }
};

// Initialize on DOM content loaded
document.addEventListener('DOMContentLoaded', () => {
    initializeProfileFunctionality();
    console.log('Profile functionality loaded, fetchAndDisplayUserProfile is defined:', typeof window.fetchAndDisplayUserProfile);
});
