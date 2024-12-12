// Initialize settings modal
const settingsModal = new bootstrap.Modal(document.getElementById('settingsModal'));

// Load saved settings
document.addEventListener('DOMContentLoaded', function() {
    // Load user profile data
    fetch('/api/user/profile')
        .then(response => response.json())
        .then(data => {
            document.getElementById('displayName').value = data.display_name || '';
            document.getElementById('bioText').value = data.bio || '';
            document.getElementById('location').value = data.location || '';
            document.getElementById('currentAvatar').src = data.avatar || '/static/images/default-avatar.svg';
            
            if (data.accent_color) {
                document.getElementById('accentColor').value = data.accent_color;
                updateThemePreview(data.accent_color);
            }
        })
        .catch(error => console.error('Error loading profile:', error));

    // Load theme setting
    const savedTheme = localStorage.getItem('theme') || 'dark';
    document.getElementById('themeSelect').value = savedTheme;
    document.documentElement.setAttribute('data-theme', savedTheme);

    // Load notification settings
    const notifyMessages = localStorage.getItem('notifyMessages') !== 'false';
    const notifyMentions = localStorage.getItem('notifyMentions') !== 'false';
    document.getElementById('notifyMessages').checked = notifyMessages;
    document.getElementById('notifyMentions').checked = notifyMentions;

    // Avatar upload handler
    document.getElementById('avatarUpload').addEventListener('change', function(e) {
        const file = e.target.files[0];
        if (file) {
            const formData = new FormData();
            formData.append('avatar', file);

            fetch('/api/user/update_avatar', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                document.getElementById('currentAvatar').src = data.avatar_url;
                // Update avatar in navigation
                document.querySelector('.nav-avatar').src = data.avatar_url;
            })
            .catch(error => console.error('Error uploading avatar:', error));
        }
    });

    // Accent color change handler
    document.getElementById('accentColor').addEventListener('input', function(e) {
        updateThemePreview(e.target.value);
    });

    // Save settings button handler
    document.getElementById('saveSettings').addEventListener('click', function() {
        const theme = document.getElementById('themeSelect').value;
        const notifyMessages = document.getElementById('notifyMessages').checked;
        const notifyMentions = document.getElementById('notifyMentions').checked;
        const displayName = document.getElementById('displayName').value;
        const bio = document.getElementById('bioText').value;
        const location = document.getElementById('location').value;
        const accentColor = document.getElementById('accentColor').value;

        // Save to localStorage
        localStorage.setItem('theme', theme);
        localStorage.setItem('notifyMessages', notifyMessages);
        localStorage.setItem('notifyMentions', notifyMentions);

        // Apply theme
        document.documentElement.setAttribute('data-theme', theme);

        // Save profile updates
        fetch('/api/user/update_profile', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                display_name: displayName,
                bio: bio,
                location: location,
                accent_color: accentColor,
                theme: theme,
                notify_messages: notifyMessages,
                notify_mentions: notifyMentions
            })
        })
        .then(response => response.json())
        .then(data => {
            console.log('Profile updated successfully:', data);
            // Update navigation avatar if display name changed
            if (data.display_name) {
                document.querySelector('.profile-username').textContent = data.display_name;
            }
        })
        .catch(error => console.error('Error updating profile:', error));

        // Close modal
        settingsModal.hide();

        // Notify user
        socket.emit('user_settings_updated', {
            theme,
            notifyMessages,
            notifyMentions,
            displayName,
            bio,
            location,
            accentColor
        });
    });

    // Theme select change handler
    document.getElementById('themeSelect').addEventListener('change', function(e) {
        document.documentElement.setAttribute('data-theme', e.target.value);
    });
});

// Helper function to update theme preview
function updateThemePreview(color) {
    document.documentElement.style.setProperty('--primary-color', color);
    document.documentElement.style.setProperty('--primary-transparent', `${color}1A`);
    document.documentElement.style.setProperty('--primary-transparent-hover', `${color}26`);
}
