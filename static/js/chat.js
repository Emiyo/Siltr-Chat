document.addEventListener('DOMContentLoaded', () => {
    const socket = io();
    let username = '';
    let messageHistory = [];
    let historyIndex = -1;
    
    // DOM Elements
    const usernameModal = new bootstrap.Modal(document.getElementById('usernameModal'));
    const usernameForm = document.getElementById('usernameForm');
    const messageForm = document.getElementById('messageForm');
    const messageInput = document.getElementById('messageInput');
    const messageContainer = document.getElementById('messageContainer');
    const userList = document.getElementById('userList');

    // Show username modal on load
    usernameModal.show();

    // Handle username submission
    usernameForm.addEventListener('submit', (e) => {
        e.preventDefault();
        username = document.getElementById('usernameInput').value.trim();
        if (username) {
            socket.emit('join', { username });
            usernameModal.hide();
            addMessage({
                type: 'system',
                text: 'Type /help for available commands',
                timestamp: new Date().toISOString()
            });
        }
    });

    // Handle message submission
    messageForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const message = messageInput.value.trim();
        if (message) {
            messageHistory.push(message);
            historyIndex = messageHistory.length;
            socket.emit('message', { text: message });
            messageInput.value = '';
        }
    });

    // Handle command history with up/down arrows
    messageInput.addEventListener('keydown', (e) => {
        if (e.key === 'ArrowUp') {
            e.preventDefault();
            if (historyIndex > 0) {
                historyIndex--;
                messageInput.value = messageHistory[historyIndex];
            }
        } else if (e.key === 'Tab') {
            e.preventDefault();
            // Add tab completion here if needed
        } else if (e.key === 'ArrowDown') {
            e.preventDefault();
            if (historyIndex < messageHistory.length - 1) {
                historyIndex++;
                messageInput.value = messageHistory[historyIndex];
            } else {
                historyIndex = messageHistory.length;
                messageInput.value = '';
            }
        }
    });

    // Socket event handlers
    socket.on('connect', () => {
        addMessage({
            type: 'system',
            text: 'Connected to server',
            timestamp: new Date().toISOString()
        });
    });

    socket.on('disconnect', () => {
        addMessage({
            type: 'system',
            text: 'Disconnected from server',
            timestamp: new Date().toISOString()
        });
    });

    socket.on('message_history', (data) => {
        messageContainer.innerHTML = '';
        data.messages.forEach(message => addMessage(message));
    });

    socket.on('new_message', (message) => {
        addMessage(message);
        scrollToBottom();
    });

    socket.on('user_list', (data) => {
        updateUserList(data.users);
    });

    socket.on('clear_chat', () => {
        messageContainer.innerHTML = '';
        addMessage({
            type: 'system',
            text: 'Terminal cleared',
            timestamp: new Date().toISOString()
        });
    });

    // Helper functions
    function addMessage(message) {
        const messageDiv = document.createElement('div');
        const timestamp = new Date(message.timestamp).toLocaleTimeString();

        if (message.type === 'system') {
            messageDiv.className = 'message message-system';
            messageDiv.innerHTML = `[${timestamp}] ${message.text}`;
        } else {
            const isOwnMessage = message.username === username;
            messageDiv.className = `message ${isOwnMessage ? 'message-own' : 'message-other'}`;
            messageDiv.innerHTML = `[${timestamp}] ${isOwnMessage ? '' : message.username + ': '}${message.text}`;
        }

        messageContainer.appendChild(messageDiv);
    }

    function updateUserList(users) {
        userList.innerHTML = users.map(user => `
            <div class="user-item">
                <span class="user-status">></span>
                ${user.username}
            </div>
        `).join('');
    }

    function scrollToBottom() {
        messageContainer.scrollTop = messageContainer.scrollHeight;
    }
});
