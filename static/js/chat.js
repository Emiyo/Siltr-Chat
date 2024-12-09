document.addEventListener('DOMContentLoaded', () => {
    const socket = io();
    const messageForm = document.getElementById('messageForm');
    const messageInput = document.getElementById('messageInput');
    const messageContainer = document.getElementById('messageContainer');
    const userList = document.getElementById('userList');
    const usernameModal = new bootstrap.Modal(document.getElementById('usernameModal'), {
        backdrop: 'static',
        keyboard: false
    });
    let username = '';
    let user_id = null;
    const active_users = {};

    // Show login modal on page load
    usernameModal.show();

    // Handle username form submission
    document.getElementById('usernameForm').addEventListener('submit', (e) => {
        e.preventDefault();
        username = document.getElementById('usernameInput').value.trim();
        if (username) {
            usernameModal.hide();
            socket.emit('join', { username });
        }
    });
document.addEventListener('DOMContentLoaded', () => {
    const socket = io();
    let username = '';
    let user_id = null;
    let currentChannel = null;
    let categories = [];
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

    // File input element
    const fileInput = document.createElement('input');
    fileInput.type = 'file';
    fileInput.style.display = 'none';
    document.body.appendChild(fileInput);

    // Handle message submission
    messageForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const message = messageInput.value.trim();
        if (message) {
            // Check if it's a private message
            if (message.startsWith('@')) {
                const spaceIndex = message.indexOf(' ');
                if (spaceIndex > 1) {
                    const recipient = message.substring(1, spaceIndex);
                    const privateMessage = message.substring(spaceIndex + 1);
                    messageHistory.push(message);
                    historyIndex = messageHistory.length;
                    socket.emit('private_message', {
                        recipient: recipient,
                        text: privateMessage
                    });
                    messageInput.value = '';
                    return;
                }
            }
            
            // Regular message
            messageHistory.push(message);
            historyIndex = messageHistory.length;
            socket.emit('message', { text: message });
            messageInput.value = '';
        }
    });

    // Handle file attachment
    document.getElementById('attachButton').addEventListener('click', () => {
        fileInput.click();
    });

    fileInput.addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (file) {
            const formData = new FormData();
            formData.append('file', file);
            
            try {
                const response = await fetch('/upload', {
                    method: 'POST',
                    body: formData
                });
                
                if (response.ok) {
                    const data = await response.json();
                    // Handle voice messages differently
                    if (data.voice_url) {
                        socket.emit('message', {
                            text: 'Voice message',
                            voice_url: data.voice_url,
                            voice_duration: data.voice_duration
                        });
                    } else {
                        socket.emit('message', {
                            text: `Shared a file: ${file.name}`,
                            file_url: data.file_url
                        });
                    }
                }
            } catch (error) {
                console.error('Error uploading file:', error);
            }
            
            fileInput.value = ''; // Reset file input
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
        // Store user ID when receiving message history
        if (data.user_id) {
            user_id = data.user_id;
        }
        data.messages.forEach(message => addMessage(message));
    });

    socket.on('new_message', (message) => {
        addMessage(message);
        scrollToBottom();
    });

    let categories = [];
    let currentChannel = null;

    socket.on('user_list', (data) => {
        updateUserList(data.users);
    });

    // Categories and Channels Handling
    socket.on('categories_list', (data) => {
        console.log('Received categories:', data);
        if (data && data.categories) {
            categories = data.categories;
            updateCategoryList();
        } else {
            console.error('Invalid categories data received:', data);
        }
    });

    socket.on('category_created', (category) => {
        categories.push(category);
        updateCategoryList();
    });

    socket.on('channel_created', (channel) => {
        const category = categories.find(c => c.id === channel.category_id);
        if (category) {
            if (!category.channels) category.channels = [];
            category.channels.push(channel);
            updateCategoryList();
        }
    });

    socket.on('channel_history', (data) => {
        if (data.channel_id === currentChannel) {
            messageContainer.innerHTML = '';
            data.messages.forEach(message => addMessage(message));
            scrollToBottom();
        }
    });

    function updateCategoryList() {
        console.log('Updating category list with:', categories);
        const categoryList = document.getElementById('categoryList');
        if (!categoryList) {
            console.error('Category list element not found');
            return;
        }
        if (!Array.isArray(categories)) {
            console.error('Categories is not an array:', categories);
            return;
        }
        
        categoryList.innerHTML = categories.map(category => {
            const channels = category.channels || [];
            return `
                <div class="category-item">
                    <div class="category-header">
                        <span class="category-toggle">▼</span>
                        ${category.name}
                    </div>
                    <div class="channel-list" style="display: block;">
                        ${channels.map(channel => `
                            <div class="channel-item ${channel.id === currentChannel ? 'active' : ''}" 
                                 data-channel-id="${channel.id}">
                                ${channel.is_private ? '🔒' : '#'} ${channel.name}
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        }).join('');

        // Add event listeners
        document.querySelectorAll('.category-header').forEach(header => {
            header.addEventListener('click', (e) => {
                const channelList = header.nextElementSibling;
                const toggle = header.querySelector('.category-toggle');
                if (channelList.style.display === 'none') {
                    channelList.style.display = 'block';
                    toggle.textContent = '▼';
                } else {
                    channelList.style.display = 'none';
                    toggle.textContent = '▶';
                }
            });
        });

        document.querySelectorAll('.channel-item').forEach(item => {
            item.addEventListener('click', () => {
                const channelId = parseInt(item.dataset.channelId);
                if (currentChannel !== channelId) {
                    if (currentChannel) {
                        socket.emit('leave_channel', { channel_id: currentChannel });
                    }
                    currentChannel = channelId;
                    socket.emit('join_channel', { channel_id: channelId });
                    document.querySelectorAll('.channel-item').forEach(ch => 
                        ch.classList.toggle('active', ch.dataset.channelId === String(channelId))
                    );
                }
            });
        });

        // Show moderator controls if user is a moderator
        const moderatorControls = document.getElementById('moderatorControls');
        if (user_id && active_users[user_id]?.is_moderator) {
            moderatorControls.classList.remove('d-none');
        }
    }

    // Request initial categories list when connected
    socket.on('connect', () => {
        socket.emit('get_categories');
    });

    // Create category modal handlers
    document.getElementById('createCategoryBtn')?.addEventListener('click', () => {
        const name = prompt('Enter category name:');
        const description = prompt('Enter category description (optional):');
        if (name) {
            socket.emit('create_category', { name, description });
        }
    });

    // Create channel modal handlers
    document.getElementById('createChannelBtn')?.addEventListener('click', () => {
        const categoryId = prompt('Enter category ID:');
        const name = prompt('Enter channel name:');
        const description = prompt('Enter channel description (optional):');
        const isPrivate = confirm('Should this be a private channel?');
        
        if (categoryId && name) {
            socket.emit('create_channel', {
                category_id: parseInt(categoryId),
                name,
                description,
                is_private: isPrivate
            });
        }
    });
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
        let messageContent = message.text;
        let messageHeader = '';

        // Prepare message content based on type
        if (message.voice_url) {
            messageContent = `
                <div class="message-content">${message.text}</div>
                <div class="voice-message">
                    <audio controls>
                        <source src="${message.voice_url}" type="audio/mpeg">
                        Your browser does not support the audio element.
                    </audio>
                    ${message.voice_duration ? `<span class="voice-duration">${message.voice_duration.toFixed(1)}s</span>` : ''}
                </div>`;
        } else if (message.file_url) {
            messageContent = `
                <div class="message-content">${message.text}</div>
                <a href="${message.file_url}" target="_blank" class="file-attachment">
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-file-earmark" viewBox="0 0 16 16">
                        <path d="M14 4.5V14a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V2a2 2 0 0 1 2-2h5.5L14 4.5zm-3 0A1.5 1.5 0 0 1 9.5 3V1H4a1 1 0 0 0-1 1v12a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V4.5h-2z"/>
                    </svg>
                    Download Attachment
                </a>`;
        } else {
            messageContent = `<div class="message-content">${message.text}</div>`;
        }

        if (message.type === 'system') {
            messageDiv.className = 'message message-system';
            messageDiv.innerHTML = `
                <div class="message-timestamp">${timestamp}</div>
                ${messageContent}`;
        } else if (message.type === 'private') {
            messageDiv.className = 'message message-private';
            const isOwnMessage = message.sender_id === user_id;
            const otherUser = isOwnMessage ? message.receiver_username : message.sender_username;
            messageHeader = `
                <div class="message-timestamp">
                    <span class="message-username">${isOwnMessage ? username : otherUser}</span> • ${timestamp}
                </div>`;
            messageDiv.innerHTML = `
                ${messageHeader}
                <div class="message-private-indicator">🔒 Private message ${isOwnMessage ? 'to' : 'from'} ${otherUser}</div>
                ${messageContent}`;
        } else {
            const isOwnMessage = message.sender_id === user_id;
            messageDiv.className = `message ${isOwnMessage ? 'message-own' : 'message-other'}`;
            if (!isOwnMessage) {
                messageHeader = `
                    <div class="message-timestamp">
                        <span class="message-username">${message.sender_username || username}</span> • ${timestamp}
                    </div>`;
            } else {
                messageHeader = `<div class="message-timestamp">${timestamp}</div>`;
            }
            messageDiv.innerHTML = `${messageHeader}${messageContent}`;
        }

        // Add reaction buttons if not a system message
        if (message.type !== 'system') {
            const reactionDiv = document.createElement('div');
            reactionDiv.className = 'message-reactions';
            const reactions = message.reactions || {};
            
            // Display existing reactions
            Object.entries(reactions).forEach(([reaction, users]) => {
                const count = Array.isArray(users) ? users.length : 0;
                reactionDiv.innerHTML += `<span class="reaction" data-reaction="${reaction}">${reaction} ${count}</span>`;
            });

            // Add reaction button
            const addReactionBtn = document.createElement('button');
            addReactionBtn.className = 'btn btn-sm btn-link add-reaction';
            addReactionBtn.innerHTML = '➕';
            addReactionBtn.onclick = () => addReaction(message.id);
            reactionDiv.appendChild(addReactionBtn);

            messageDiv.appendChild(reactionDiv);
        }

        messageContainer.appendChild(messageDiv);
    }

    function addReaction(messageId) {
        // Simple reaction picker
        const reactions = ['👍', '❤️', '😄', '🎉', '👀'];
        const picker = document.createElement('div');
        picker.className = 'reaction-picker';
        picker.innerHTML = reactions.map(r => `<span class="reaction-option">${r}</span>`).join('');
        
        // Position the picker
        const rect = event.target.getBoundingClientRect();
        picker.style.position = 'absolute';
        picker.style.left = rect.left + 'px';
        picker.style.top = (rect.top - 40) + 'px';
        
        // Handle reaction selection
        picker.onclick = (e) => {
            if (e.target.classList.contains('reaction-option')) {
                const reaction = e.target.textContent;
                socket.emit('add_reaction', {
                    message_id: messageId,
                    reaction: reaction
                });
                document.body.removeChild(picker);
            }
        };
        
        document.body.appendChild(picker);
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
