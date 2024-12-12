// Initialize settings modal
const settingsModal = new bootstrap.Modal(document.getElementById('settingsModal'));

// Load saved settings
document.addEventListener('DOMContentLoaded', function() {
    // Load theme setting
    const savedTheme = localStorage.getItem('theme') || 'dark';
    document.getElementById('themeSelect').value = savedTheme;
    document.documentElement.setAttribute('data-theme', savedTheme);

    // Load notification settings
    const notifyMessages = localStorage.getItem('notifyMessages') !== 'false';
    const notifyMentions = localStorage.getItem('notifyMentions') !== 'false';
    document.getElementById('notifyMessages').checked = notifyMessages;
    document.getElementById('notifyMentions').checked = notifyMentions;

    // Save settings button handler
    document.getElementById('saveSettings').addEventListener('click', function() {
        const theme = document.getElementById('themeSelect').value;
        const notifyMessages = document.getElementById('notifyMessages').checked;
        const notifyMentions = document.getElementById('notifyMentions').checked;

        // Save to localStorage
        localStorage.setItem('theme', theme);
        localStorage.setItem('notifyMessages', notifyMessages);
        localStorage.setItem('notifyMentions', notifyMentions);

        // Apply theme
        document.documentElement.setAttribute('data-theme', theme);

        // Close modal
        settingsModal.hide();

        // Notify user
        socket.emit('user_settings_updated', {
            theme,
            notifyMessages,
            notifyMentions
        });
    });

    // Theme select change handler
    document.getElementById('themeSelect').addEventListener('change', function(e) {
        document.documentElement.setAttribute('data-theme', e.target.value);
    });
});
