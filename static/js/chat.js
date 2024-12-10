document.addEventListener('DOMContentLoaded', () => {
    const socket = io();
    const messageForm = document.getElementById('messageForm');
    const messageInput = document.getElementById('messageInput');
    const messageContainer = document.getElementById('messages');
    const userList = document.getElementById('userList');
    const usernameModal = new bootstrap.Modal(document.getElementById('usernameModal'));
    
    let username = '';
    let user_id = null;
    let currentChannel = null;
    let categories = [];
    let messageHistory = [];
    let historyIndex = -1;
    
    // Encryption keys
    let keyPair = null;
    let channelKeys = new Map();
    let userPublicKeys = new Map();

    // Show login modal on page load
    usernameModal.show();

    // Handle username submission
    document.getElementById('usernameForm').addEventListener('submit', (e) => {
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

    // File handling setup
    const fileInput = document.createElement('input');
    fileInput.type = 'file';
    fileInput.style.display = 'none';
    document.body.appendChild(fileInput);

    // Message form handling
    messageForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const message = messageInput.value.trim();
        if (message) {
            if (message.startsWith('@')) {
                const spaceIndex = message.indexOf(' ');
                if (spaceIndex > 1) {
                    const recipient = message.substring(1, spaceIndex);
                    const privateMessage = message.substring(spaceIndex + 1);
                    
                    // Encrypt private message with recipient's public key
                    const recipientPublicKey = userPublicKeys.get(recipient);
                    if (recipientPublicKey) {
                        const encryptedData = await encryptMessage(privateMessage, recipientPublicKey);
                        socket.emit('private_message', {
                            recipient: recipient,
                            encrypted: encryptedData.encrypted,
                            iv: encryptedData.iv
                        });
                    } else {
                        addMessage({
                            type: 'system',
                            text: 'Cannot send encrypted message: Recipient key not found',
                            timestamp: new Date().toISOString()
                        });
                    }
                }
            } else {
                if (currentChannel) {
                    const channelKey = channelKeys.get(currentChannel);
                    if (channelKey) {
                        const encryptedData = await encryptMessage(message, channelKey);
                        socket.emit('message', {
                            encrypted: encryptedData.encrypted,
                            iv: encryptedData.iv,
                            channel_id: currentChannel
                        });
                    } else {
                        addMessage({
                            type: 'system',
                            text: 'Cannot send encrypted message: Channel key not found',
                            timestamp: new Date().toISOString()
                        });
                    }
                } else {
                    addMessage({
                        type: 'system',
                        text: 'Please select a channel first',
                        timestamp: new Date().toISOString()
                    });
                }
            }
            messageHistory.push(message);
            historyIndex = messageHistory.length;
            messageInput.value = '';
        }
    });

    // File attachment handling
    document.getElementById('attachButton')?.addEventListener('click', () => {
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
                    if (data.voice_url) {
                        socket.emit('message', {
                            text: 'Voice message',
                            voice_url: data.voice_url,
                            voice_duration: data.voice_duration,
                            channel_id: currentChannel
                        });
                    } else {
                        socket.emit('message', {
                            text: `Shared a file: ${file.name}`,
                            file_url: data.file_url,
                            channel_id: currentChannel
                        });
                    }
                }
            } catch (error) {
                console.error('Error uploading file:', error);
            }
            fileInput.value = '';
        }
    });

    // Command history handling
    messageInput.addEventListener('keydown', (e) => {
        if (e.key === 'ArrowUp') {
            e.preventDefault();
            if (historyIndex > 0) {
                historyIndex--;
                messageInput.value = messageHistory[historyIndex];
            }
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
    socket.on('connect', async () => {
        // Generate key pair for this session
        const publicKeyStr = await generateKeyPair();
        
        addMessage({
            type: 'system',
            text: 'Connected to server',
            timestamp: new Date().toISOString()
        });

        // Share public key with server
        socket.emit('share_public_key', { publicKey: publicKeyStr });
    });

    // Handle received public keys
    socket.on('public_key_shared', (data) => {
        const { userId, publicKey } = data;
        userPublicKeys.set(userId, publicKey);
    });

    // Handle channel key distribution
    socket.on('channel_key', async (data) => {
        try {
            const { channelId, encryptedKey } = data;
            const key = await window.crypto.subtle.decrypt(
                { name: "RSA-OAEP" },
                keyPair.privateKey,
                Uint8Array.from(atob(encryptedKey), c => c.charCodeAt(0))
            );
            channelKeys.set(channelId, key);
        } catch (error) {
            console.error('Error processing channel key:', error);
        }
    });
    
    socket.on('message_history', (data) => {
        messageContainer.innerHTML = '';
        if (data.user_id) {
            user_id = data.user_id;
            // Request categories when user_id is received
            socket.emit('get_categories');
        }
        data.messages.forEach(message => addMessage(message));
        scrollToBottom();
    });

    socket.on('join', (data) => {
        if (data.username) {
            // Also request categories on successful join
            socket.emit('get_categories');
        }
    });

    socket.on('disconnect', () => {
        addMessage({
            type: 'system',
            text: 'Disconnected from server',
            timestamp: new Date().toISOString()
        });
    });

    socket.on('new_message', async (message) => {
        if (message.encrypted && message.iv) {
            try {
                let decryptionKey;
                if (message.type === 'private') {
                    decryptionKey = keyPair.privateKey;
                } else {
                    decryptionKey = channelKeys.get(message.channel_id);
                }
                
                if (decryptionKey) {
                    const decryptedText = await decryptMessage(
                        { encrypted: message.encrypted, iv: message.iv },
                        decryptionKey
                    );
                    message.text = decryptedText;
                } else {
                    message.text = '[Encrypted message - key not available]';
                }
            } catch (error) {
                console.error('Error decrypting message:', error);
                message.text = '[Decryption failed]';
            }
        }
        addMessage(message);
        scrollToBottom();
    });

    socket.on('user_list', (data) => {
        updateUserList(data.users);
    });

    // Categories and Channels
    socket.on('categories_list', (data) => {
        if (data && data.categories) {
            categories = data.categories;
            updateCategoryList();
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

    socket.on('clear_chat', () => {
        messageContainer.innerHTML = '';
        addMessage({
            type: 'system',
            text: 'Chat cleared',
            timestamp: new Date().toISOString()
        });
    });

    // Helper Functions
    function updateCategoryList() {
        const categoryList = document.getElementById('categoryList');
        if (!categoryList || !Array.isArray(categories)) return;
        
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
            header.addEventListener('click', () => {
                const channelList = header.nextElementSibling;
                const toggle = header.querySelector('.category-toggle');
                channelList.style.display = channelList.style.display === 'none' ? 'block' : 'none';
                toggle.textContent = channelList.style.display === 'none' ? '▶' : '▼';
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
                    messageContainer.innerHTML = '';
                    addMessage({
                        type: 'system',
                        text: `Joined channel #${item.textContent.trim()}`,
                        timestamp: new Date().toISOString()
                    });
                    socket.emit('join_channel', { channel_id: channelId });
                    document.querySelectorAll('.channel-item').forEach(ch => 
                        ch.classList.toggle('active', ch.dataset.channelId === String(channelId))
                    );
                }
            });
        });
    }

    function addMessage(message) {
        const messageDiv = document.createElement('div');
        const timestamp = new Date(message.timestamp).toLocaleTimeString();
        let messageContent = message.text;
        let messageHeader = '';

        // Handle different message types
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
            messageHeader = isOwnMessage ? 
                `<div class="message-timestamp">${timestamp}</div>` :
                `<div class="message-timestamp">
                    <span class="message-username">${message.sender_username || username}</span> • ${timestamp}
                </div>`;
            messageDiv.innerHTML = `${messageHeader}${messageContent}`;
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

    // Encryption utilities
    async function generateKeyPair() {
        try {
            console.log('Generating new key pair...');
            keyPair = await window.crypto.subtle.generateKey(
                {
                    name: "RSA-OAEP",
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: "SHA-256",
                },
                true,
                ["encrypt", "decrypt"]
            );
            
            // Export public key for sharing
            const exported = await window.crypto.subtle.exportKey(
                "spki",
                keyPair.publicKey
            );
            const publicKeyString = btoa(String.fromCharCode(...new Uint8Array(exported)));
            console.log('Key pair generated successfully');
            return publicKeyString;
        } catch (error) {
            console.error('Error generating key pair:', error);
            throw new Error('Failed to generate key pair');
        }
    }

    async function generateChannelKey() {
        return await window.crypto.subtle.generateKey(
            {
                name: "AES-GCM",
                length: 256
            },
            true,
            ["encrypt", "decrypt"]
        );
    }

    async function encryptMessage(text, key) {
        const encoder = new TextEncoder();
        const data = encoder.encode(text);
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        
        const encryptedContent = await window.crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            key,
            data
        );

        return {
            encrypted: btoa(String.fromCharCode(...new Uint8Array(encryptedContent))),
            iv: btoa(String.fromCharCode(...iv))
        };
    }

    async function decryptMessage(encryptedObj, key) {
        try {
            const encryptedData = Uint8Array.from(atob(encryptedObj.encrypted), c => c.charCodeAt(0));
            const iv = Uint8Array.from(atob(encryptedObj.iv), c => c.charCodeAt(0));
            
            const decrypted = await window.crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: iv
                },
                key,
                encryptedData
            );

            const decoder = new TextDecoder();
            return decoder.decode(decrypted);
        } catch (error) {
            console.error('Decryption failed:', error);
            return '[Unable to decrypt message]';
        }
    }

    function scrollToBottom() {
        messageContainer.scrollTop = messageContainer.scrollHeight;
    }
});