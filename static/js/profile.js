// Profile functionality
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
};

// Initialize on DOM content loaded
document.addEventListener('DOMContentLoaded', () => {
    initializeProfileFunctionality();
    console.log('Profile functionality loaded, fetchAndDisplayUserProfile is defined:', typeof window.fetchAndDisplayUserProfile);
});
