// User Profile Management
let socket;

document.addEventListener('DOMContentLoaded', function() {
    // Profile display functionality
    async function displayUserProfile(userId) {
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
            const statusElement = document.getElementById('modalStatus');
            if (statusElement) {
                statusElement.innerHTML = `
                    <div class="status-container">
                        ${userData.status || 'Set a custom status'}
                    </div>
                `;
            }

            // Set avatar
            const avatarElement = document.getElementById('modalUserAvatar');
            if (avatarElement) {
                avatarElement.src = userData.avatar || '/static/images/default-avatar.png';
            }

            // Show presence
            const presenceElement = document.getElementById('modalPresence');
            if (presenceElement) {
                presenceElement.textContent = userData.presence_state || 'online';
            }

            // Show bio and location
            if (userData.bio) {
                document.getElementById('modalBio').textContent = userData.bio;
            }
            if (userData.location) {
                document.getElementById('modalLocation').textContent = userData.location;
            }

            // Show modal
            const bootstrapModal = new bootstrap.Modal(modal);
            bootstrapModal.show();
            
            console.log('Discord-style profile modal displayed for user:', userData.username);
        } catch (error) {
            console.error('Error fetching user profile:', error);
        }
    }

    // Close modal functionality
    const modals = document.querySelectorAll('.modal');
    modals.forEach(modal => {
        const closeBtn = modal.querySelector('.close');
        if (closeBtn) {
            closeBtn.onclick = () => {
                const bootstrapModal = bootstrap.Modal.getInstance(modal);
                if (bootstrapModal) {
                    bootstrapModal.hide();
                }
            };
        }
    });

    // Expose the profile display function globally
    window.displayUserProfile = displayUserProfile;
});
