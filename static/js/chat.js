document.addEventListener('DOMContentLoaded', () => {
    const socket = io();
    
    // DOM Elements
    const messageForm = document.getElementById('messageForm');
    const messageInput = document.getElementById('messageInput');
    const messageContainer = document.getElementById('messageContainer');
    const userList = document.getElementById('userList');
    const usernameModal = new bootstrap.Modal(document.getElementById('usernameModal'), {
        backdrop: 'static',
        keyboard: false
    });

    // State variables
    let username = '';
    let user_id = null;
    let currentChannel = null;
    let categories = [];
    let messageHistory = [];
    let historyIndex = -1;
    
    // Encryption state
    let keyPair = null;
    let channelKeys = new Map();  // Store symmetric keys for each channel

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
            // Handle commands first
            if (message.startsWith('/')) {
                socket.emit('message', {
                    text: message,
                    channel_id: currentChannel
                });
                messageHistory.push(message);
                historyIndex = messageHistory.length;
                messageInput.value = '';
                return;
            }

            // Handle private messages
            if (message.startsWith('@')) {
                const spaceIndex = message.indexOf(' ');
                if (spaceIndex > 1) {
                    const recipient = message.substring(1, spaceIndex);
                    const privateMessage = message.substring(spaceIndex + 1);
                    socket.emit('private_message', {
                        recipient: recipient,
                        text: privateMessage
                    });
                }
                messageHistory.push(message);
                historyIndex = messageHistory.length;
                messageInput.value = '';
                return;
            }

            // Handle regular messages with encryption
            if (!currentChannel) {
                addMessage({
                    type: 'system',
                    text: 'Please select a channel first',
                    timestamp: new Date().toISOString()
                });
                return;
            }

            try {
                // Get or create symmetric key for the channel
                let symmetricKey = channelKeys.get(currentChannel);
                if (!symmetricKey) {
                    symmetricKey = await CryptoManager.generateSymmetricKey();
                    channelKeys.set(currentChannel, symmetricKey);
                }

                // Create message payload
                const messagePayload = {
                    content: message,
                    timestamp: new Date().toISOString()
                };

                // Encrypt the message payload
                const encryptedMessage = await CryptoManager.encryptMessage(
                    JSON.stringify(messagePayload),
                    symmetricKey
                );
                
                const exportedKey = await CryptoManager.exportSymmetricKey(symmetricKey);

                const messageData = {
                    text: encryptedMessage,
                    channel_id: currentChannel,
                    encryption_key: exportedKey,
                    is_encrypted: true
                };

                socket.emit('message', messageData);
            } catch (error) {
                console.error('Encryption error:', error);
                addMessage({
                    type: 'system',
                    text: 'Failed to encrypt message: ' + error.message,
                    timestamp: new Date().toISOString()
                });
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
        if (!file) {
            return;
        }

        if (!currentChannel) {
            addMessage({
                type: 'system',
                text: 'Please select a channel before uploading files',
                timestamp: new Date().toISOString()
            });
            fileInput.value = '';
            return;
        }

        try {
            // Show upload status
            addMessage({
                type: 'system',
                text: 'Uploading file...',
                timestamp: new Date().toISOString()
            });

            // Get or create symmetric key for the channel
            let symmetricKey = channelKeys.get(currentChannel);
            if (!symmetricKey) {
                symmetricKey = await CryptoManager.generateSymmetricKey();
                channelKeys.set(currentChannel, symmetricKey);
            }

            // Encrypt the file
            const encryptedFile = await CryptoManager.encryptFile(file, symmetricKey);
            
            // Create form data with encrypted file
            const formData = new FormData();
            formData.append('file', encryptedFile.blob, file.name);
            formData.append('original_type', file.type);
            formData.append('original_name', file.name);
            
            console.log('Uploading file with metadata:', {
                name: file.name,
                type: file.type,
                size: encryptedFile.blob.size
            });
            
            const response = await fetch('/upload', {
                method: 'POST',
                body: formData
            });
            
            if (!response.ok) {
                throw new Error(`Upload failed: ${response.statusText}`);
            }

            const data = await response.json();
            if (!data.file_url && !data.voice_url) {
                throw new Error('Server response missing file URL');
            }

            const exportedKey = await CryptoManager.exportSymmetricKey(symmetricKey);
            
            if (file.type.startsWith('audio/')) {
                socket.emit('message', {
                    text: 'Voice message',
                    voice_url: data.voice_url,
                    voice_duration: data.voice_duration,
                    channel_id: currentChannel,
                    is_encrypted: true,
                    encryption_key: exportedKey,
                    original_type: file.type
                });
            } else {
                socket.emit('message', {
                    text: `Shared a file: ${file.name}`,
                    file_url: data.file_url,
                    channel_id: currentChannel,
                    is_encrypted: true,
                    encryption_key: exportedKey,
                    original_type: file.type,
                    original_name: file.name
                });
            }

            addMessage({
                type: 'system',
                text: 'File uploaded successfully',
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            console.error('Error uploading file:', error);
            addMessage({
                type: 'system',
                text: 'Failed to upload file: ' + error.message,
                timestamp: new Date().toISOString()
            });
        }
        fileInput.value = '';
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
    socket.on('connect', () => {
        addMessage({
            type: 'system',
            text: 'Connected to server',
            timestamp: new Date().toISOString()
        });
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

    socket.on('message_history', (data) => {
        messageContainer.innerHTML = '';
        if (data.user_id) {
            user_id = data.user_id;
        }
        data.messages.forEach(message => addMessage(message));
        scrollToBottom();
    });

    socket.on('new_message', (message) => {
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

        // Show moderator controls if user is a moderator
        const moderatorControls = document.getElementById('moderatorControls');
        if (moderatorControls && user_id &&  document.getElementById('moderatorControls') ) {
            moderatorControls.classList.remove('d-none');
        }
    }

    async function addMessage(message) {
        const messageDiv = document.createElement('div');
        const timestamp = new Date(message.timestamp).toLocaleTimeString();
        let messageContent = message.text;
        let messageHeader = '';

        // Handle encrypted messages
        if (message.is_encrypted && message.encryption_key) {
            try {
                console.log('Attempting to decrypt message:', {
                    encryptedText: message.text,
                    hasKey: !!message.encryption_key
                });
                
                const symmetricKey = await CryptoManager.importSymmetricKey(message.encryption_key);
                console.log('Symmetric key imported successfully');
                
                const decryptedContent = await CryptoManager.decryptMessage(message.text, symmetricKey);
                console.log('Decrypted content:', decryptedContent);
                
                if (decryptedContent) {
                    try {
                        const messagePayload = JSON.parse(decryptedContent);
                        console.log('Parsed message payload:', messagePayload);
                        messageContent = messagePayload.content;
                    } catch (parseError) {
                        console.error('Error parsing decrypted message:', parseError);
                        messageContent = '[Message format error]';
                    }
                } else {
                    console.error('Decryption returned null');
                    messageContent = '[Unable to decrypt message]';
                }
            } catch (error) {
                console.error('Decryption error:', error);
                messageContent = '[Unable to decrypt message: ' + error.message + ']';
            }
        }

        // Handle different message types
        if (message.voice_url || message.file_url) {
            const url = message.voice_url || message.file_url;
            const isEncrypted = message.is_encrypted && message.encryption_key;

            if (isEncrypted) {
                // Create unique ID for this message's download button
                const downloadId = `download-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
                
                if (message.voice_url) {
                    messageContent = `
                        <div class="message-content">${message.text}</div>
                        <div class="voice-message">
                            <button id="${downloadId}" class="btn btn-sm btn-terminal encrypted-download-btn">
                                Download Encrypted Voice Message
                            </button>
                            ${message.voice_duration ? `<span class="voice-duration">${message.voice_duration.toFixed(1)}s</span>` : ''}
                        </div>`;
                } else if (message.original_type && message.original_type.startsWith('image/')) {
                    messageContent = `
                        <div class="message-content">${message.text}</div>
                        <div class="image-preview">
                            <div id="image-${downloadId}" class="encrypted-image-placeholder">
                                Loading encrypted image...
                            </div>
                        </div>
                        <button id="${downloadId}" class="btn btn-sm btn-terminal encrypted-download-btn">
                            Download Original Image
                        </button>`;
                } else {
                    messageContent = `
                        <div class="message-content">${message.text}</div>
                        <button id="${downloadId}" class="btn btn-sm btn-terminal encrypted-download-btn">
                            Download Encrypted File
                        </button>`;
                }

                // Add the message data to the button after it's added to DOM
                setTimeout(() => {
                    const downloadButton = document.getElementById(downloadId);
                    if (downloadButton) {
                        downloadButton.addEventListener('click', async (e) => {
                            e.preventDefault();
                            try {
                                console.log('Starting file download process');
                                console.log('Encryption key:', message.encryption_key);
                                
                                if (!message.encryption_key) {
                                    throw new Error('Missing encryption key');
                                }

                                const symmetricKey = await CryptoManager.importSymmetricKey(message.encryption_key);
                                console.log('Symmetric key imported successfully');

                                console.log('Fetching encrypted file from:', url);
                                const response = await fetch(url);
                                if (!response.ok) {
                                    throw new Error(`Failed to fetch file: ${response.statusText}`);
                                }

                                const encryptedBlob = await response.blob();
                                console.log('Encrypted file size:', encryptedBlob.size);

                                if (encryptedBlob.size === 0) {
                                    throw new Error('Received empty file');
                                }

                                console.log('Starting file decryption');
                                const decryptedBlob = await CryptoManager.decryptFile(
                                    encryptedBlob,
                                    symmetricKey,
                                    message.original_type || 'application/octet-stream'
                                );
                                console.log('File decrypted successfully');

                                // Create download link for decrypted file with proper MIME type
                                const downloadUrl = URL.createObjectURL(decryptedBlob);
                                const downloadLink = document.createElement('a');
                                downloadLink.href = downloadUrl;
                                
                                // Ensure we preserve the original filename with extension
                                // Get the original filename and type
                                let filename;
                                if (message.original_name) {
                                    filename = message.original_name;
                                } else {
                                    const extension = message.original_type ? 
                                        '.' + message.original_type.split('/')[1] : 
                                        '.bin';
                                    filename = `downloaded_file${extension}`;
                                }
                                
                                console.log('Preparing download:', {
                                    originalName: message.original_name,
                                    originalType: message.original_type,
                                    filename: filename,
                                    blobType: decryptedBlob.type,
                                    blobSize: decryptedBlob.size
                                });
                                
                                // Set download attributes
                                downloadLink.setAttribute('download', filename);
                                downloadLink.type = message.original_type || 'application/octet-stream';
                                document.body.appendChild(downloadLink);

                                // Force the download with the correct extension
                                const clickEvent = new MouseEvent('click', {
                                    view: window,
                                    bubbles: true,
                                    cancelable: false
                                });
                                downloadLink.dispatchEvent(clickEvent);
                                
                                // If it's an image, create a preview
                                if (message.original_type && message.original_type.startsWith('image/')) {
                                    const imagePreview = document.getElementById(`image-${downloadId}`);
                                    if (imagePreview) {
                                        const img = document.createElement('img');
                                        img.src = downloadUrl;
                                        img.classList.add('embedded-image');
                                        img.alt = message.original_name || 'Decrypted image';
                                        imagePreview.innerHTML = '';
                                        imagePreview.appendChild(img);
                                        
                                        // Don't revoke URL for images that are being displayed
                                        document.body.removeChild(downloadLink);
                                    }
                                } else {
                                    // Clean up for non-image files
                                    setTimeout(() => {
                                        document.body.removeChild(downloadLink);
                                        URL.revokeObjectURL(downloadUrl);
                                    }, 100);
                                }
                                
                                console.log('File download/preview completed successfully');
                            } catch (error) {
                                console.error('Detailed error in file decryption:', error);
                                console.error('Error stack:', error.stack);
                                alert(`Failed to decrypt file: ${error.message}\nPlease check the browser console for more details.`);
                            }
                        });
                    }
                }, 0);
            } else {
                // Handle unencrypted files as before
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
                } else {
                    messageContent = `
                        <div class="message-content">${message.text}</div>
                        <a href="${message.file_url}" target="_blank" class="file-attachment">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-file-earmark" viewBox="0 0 16 16">
                                <path d="M14 4.5V14a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V2a2 2 0 0 1 2-2h5.5L14 4.5zm-3 0A1.5 1.5 0 0 1 9.5 3V1H4a1 1 0 0 0-1 1v12a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V4.5h-2z"/>
                            </svg>
                            Download Attachment
                        </a>`;
                }
            }
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

    function scrollToBottom() {
        messageContainer.scrollTop = messageContainer.scrollHeight;
    }
});