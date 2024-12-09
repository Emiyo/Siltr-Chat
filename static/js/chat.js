document.addEventListener('DOMContentLoaded', () => {
    const socket = io();
    let username = '';
    
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
        }
    });

    // Handle message submission
    messageForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const message = messageInput.value.trim();
        if (message) {
            socket.emit('message', { text: message });
            messageInput.value = '';
        }
    });

    // Socket event handlers
    socket.on('connect', () => {
        console.log('Connected to server');
    });

    socket.on('disconnect', () => {
        console.log('Disconnected from server');
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
    });

    // Helper functions
    function addMessage(message) {
        const messageDiv = document.createElement('div');
        const timestamp = new Date(message.timestamp).toLocaleTimeString();

        if (message.type === 'system') {
            messageDiv.className = 'message message-system';
            messageDiv.innerHTML = `
                <div>${message.text}</div>
                <div class="timestamp">${timestamp}</div>
            `;
        } else {
            const isOwnMessage = message.username === username;
            messageDiv.className = `message ${isOwnMessage ? 'message-own' : 'message-other'} 
                                  ${isOwnMessage ? 'text-end' : 'text-start'}`;
            messageDiv.innerHTML = `
                <div>
                    ${!isOwnMessage ? `<small class="text-muted">${message.username}</small>` : ''}
                    <div class="message-bubble">
                        ${message.text}
                    </div>
                    <div class="timestamp">${timestamp}</div>
                </div>
            `;
        }

        messageContainer.appendChild(messageDiv);
    }

    function updateUserList(users) {
        userList.innerHTML = users.map(user => `
            <li class="list-group-item">
                <div class="user-item">
                    <span class="user-status"></span>
                    ${user.username}
                </div>
            </li>
        `).join('');
    }

    function scrollToBottom() {
        messageContainer.scrollTop = messageContainer.scrollHeight;
    }
});
