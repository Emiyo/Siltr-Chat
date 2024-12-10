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
        console.log('File selected:', file ? {
            name: file.name,
            type: file.type,
            size: file.size,
            lastModified: new Date(file.lastModified).toISOString()
        } : 'No file selected');
        
        if (!file) {
            console.log('No file selected, returning');
            return;
        }

        if (!currentChannel) {
            console.log('No channel selected for file upload');
            addMessage({
                type: 'system',
                text: 'Please select a channel before uploading files',
                timestamp: new Date().toISOString()
            });
            fileInput.value = '';
            return;
        }
        
        console.log('Starting file upload process for channel:', currentChannel);

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
            
            // Create form data with encrypted file and metadata
            const formData = new FormData();
            formData.append('file', encryptedFile.blob, file.name);
            formData.append('original_type', file.type);
            formData.append('original_name', file.name);
            
            console.log('Uploading file with metadata:', {
                name: file.name,
                type: file.type,
                size: encryptedFile.blob.size,
                originalType: encryptedFile.originalType,
                originalName: encryptedFile.originalName
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
                // For image files, include additional metadata
                const messageData = {
                    text: `Shared a file: ${file.name}`,
                    file_url: data.file_url,
                    channel_id: currentChannel,
                    is_encrypted: true,
                    encryption_key: exportedKey,
                    original_type: file.type,
                    original_name: file.name,
                    file_metadata: {
                        type: file.type,
                        name: file.name,
                        size: file.size
                    }
                };
                
                console.log('Emitting message with file:', messageData);
                socket.emit('message', messageData);
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

        // Handle file attachments first, before any decryption
        if (message.voice_url || message.file_url) {
            // Skip decryption for file messages, handle them separately
            console.log('Processing file attachment message:', {
                hasVoice: !!message.voice_url,
                hasFile: !!message.file_url,
                isEncrypted: message.is_encrypted
            });
        }
        // Only attempt decryption for regular encrypted messages (not file attachments)
        else if (message.is_encrypted && message.encryption_key) {
            try {
                console.log('Attempting to decrypt regular message:', {
                    hasKey: !!message.encryption_key,
                    messageType: 'regular'
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
            
            // Don't try to decrypt the message text for file messages
            messageContent = message.text;

            if (isEncrypted) {
                // Create unique ID for this message's download button
                const downloadId = `download-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
                const imageId = `image-${downloadId}`;
                
                // Get file type from all possible sources
                const fileType = message.original_type || 
                               (message.file_metadata && message.file_metadata.type) || 
                               'application/octet-stream';
                
                console.log('Processing encrypted attachment:', {
                    type: fileType,
                    hasVoice: !!message.voice_url,
                    hasImage: fileType.startsWith('image/'),
                    metadata: message.file_metadata
                });
                
                if (message.voice_url) {
                    messageContent = `
                        <div class="message-content">${message.text}</div>
                        <div class="voice-message">
                            <button id="${downloadId}" class="btn btn-sm btn-terminal encrypted-download-btn">
                                Download Encrypted Voice Message
                            </button>
                            ${message.voice_duration ? `<span class="voice-duration">${message.voice_duration.toFixed(1)}s</span>` : ''}
                        </div>`;
                } else if (fileType.startsWith('image/')) {
                    console.log('Creating image preview container:', {
                        imageId: imageId,
                        downloadId: downloadId,
                        fileType: fileType,
                        originalName: message.original_name,
                        metadata: message.file_metadata
                    });
                    
                    messageContent = `
                        <div class="message-content">${message.text}</div>
                        <div class="image-preview">
                            <div id="${imageId}" class="encrypted-image-placeholder">
                                <div class="loading-spinner"></div>
                                <span>Loading encrypted image...</span>
                            </div>
                        </div>
                        <button id="${downloadId}" class="btn btn-sm btn-terminal encrypted-download-btn">
                            Download Original Image
                        </button>`;
                    
                    console.log('Image preview HTML created with IDs:', {
                        previewContainerId: imageId,
                        downloadButtonId: downloadId
                    });
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
                                console.log('Starting file decryption with params:', {
                                    blobSize: encryptedBlob.size,
                                    blobType: encryptedBlob.type,
                                    targetType: message.original_type || 'application/octet-stream'
                                });

                                const decryptedBlob = await CryptoManager.decryptFile(
                                    encryptedBlob,
                                    symmetricKey,
                                    message.original_type || 'application/octet-stream'
                                );
                                console.log('File decrypted successfully:', {
                                    decryptedSize: decryptedBlob.size,
                                    decryptedType: decryptedBlob.type
                                });

                                // Create download link for decrypted file with proper MIME type
                                const downloadUrl = URL.createObjectURL(decryptedBlob);
                                console.log('Created object URL for decrypted blob');
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
                                const targetType = message.original_type || 
                                                 (message.file_metadata && message.file_metadata.type) || 
                                                 'application/octet-stream';
                                console.log('Checking file type for preview:', {
                                    targetType,
                                    isImage: targetType.startsWith('image/'),
    // PFS message encryption
    async function encryptMessagePFS(message, recipientPublicKey) {
        try {
            // Get shared secret using recipient's public key
            const sharedSecret = await pfsManager.getSharedSecret(recipientPublicKey);
            
            // Derive encryption key from shared secret
            const encryptionKey = await window.crypto.subtle.importKey(
                "raw",
                sharedSecret,
                { name: "AES-GCM" },
                false,
                ["encrypt"]
            );
            
            // Generate IV
            const iv = window.crypto.getRandomValues(new Uint8Array(12));
            
            // Encrypt the message
            const encodedMessage = new TextEncoder().encode(message);
            const encryptedData = await window.crypto.subtle.encrypt(
                {
                    name: "AES-GCM",
                    iv: iv
                },
                encryptionKey,
                encodedMessage
            );
            
            // Combine IV and encrypted data
            const combined = new Uint8Array(iv.length + encryptedData.byteLength);
            combined.set(iv);
            combined.set(new Uint8Array(encryptedData), iv.length);
            
            return arrayBufferToBase64(combined.buffer);
        } catch (error) {
            console.error('Error encrypting message with PFS:', error);
            throw error;
        }
    }

    // PFS message decryption
    async function decryptMessagePFS(encryptedMessage, senderPublicKey) {
        try {
            // Get shared secret using sender's public key
            const sharedSecret = await pfsManager.getSharedSecret(senderPublicKey);
            
            // Derive decryption key from shared secret
            const decryptionKey = await window.crypto.subtle.importKey(
                "raw",
                sharedSecret,
                { name: "AES-GCM" },
                false,
                ["decrypt"]
            );
            
            // Decode and split IV and encrypted data
            const combined = base64ToArrayBuffer(encryptedMessage);
            const iv = combined.slice(0, 12);
            const encryptedData = combined.slice(12);
            
            // Decrypt the message
            const decryptedData = await window.crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: new Uint8Array(iv)
                },
                decryptionKey,
                encryptedData
            );
            
            return new TextDecoder().decode(decryptedData);
        } catch (error) {
            console.error('Error decrypting message with PFS:', error);
            throw error;
        }
    }

    // Handle key rotation notifications
    socket.on('new_public_key', async (data) => {
        try {
            const { sender_id, publicKey } = data;
            // Store the new public key for the sender
            userPublicKeys[sender_id] = publicKey;
            console.log(`Received new public key from user ${sender_id}`);
        } catch (error) {
            console.error('Error handling new public key:', error);
        }
    });
                                    messageType: message.original_type,
                                    metadataType: message.file_metadata?.type
                                });
                                
                                // Enhanced image type detection and logging
                                console.log('File type detection:', {
                                    targetType,
                                    originalType: message.original_type,
                                    metadataType: message.file_metadata?.type,
                                    isImage: targetType?.startsWith('image/') || message.original_type?.startsWith('image/')
                                });

                                const isImage = targetType?.startsWith('image/') || message.original_type?.startsWith('image/');
                                if (isImage) {
                                    console.log('Processing image preview:', {
                                        downloadId,
                                        type: targetType || message.original_type
                                    });
                                    
                                    // Create the message content first
                                    messageContent = `<div class="message-content">${message.text || ''}</div>
                                                    <div id="image-${downloadId}" class="image-preview">
                                                        <div class="encrypted-image-placeholder">
                                                            <div class="loading-spinner"></div>
                                                            Loading encrypted image...
                                                        </div>
                                                    </div>`;
                                    
                                    // Update message div with content
                                    if (message.type === 'system') {
                                        messageDiv.innerHTML = `
                                            <div class="message-timestamp">${timestamp}</div>
                                            ${messageContent}`;
                                    } else {
                                        messageDiv.innerHTML = `
                                            <div class="message-timestamp">
                                                <span class="message-username">${message.sender_username || username}</span> • ${timestamp}
                                            </div>
                                            ${messageContent}`;
                                    }
                                    
                                    // Now get the preview container
                                    const imagePreview = document.getElementById(`image-${downloadId}`);
                                    console.log('Preview container:', imagePreview ? 'found' : 'missing');
                                    
                                    try {
                                            
                                            const img = document.createElement('img');
                                            
                                            // Set up event handlers before setting src
                                            img.onload = () => {
                                                console.log('Image loaded successfully:', {
                                                    width: img.width,
                                                    height: img.height,
                                                    naturalWidth: img.naturalWidth,
                                                    naturalHeight: img.naturalHeight,
                                                    src: img.src.substring(0, 50) + '...'
                                                });
                                                
                                                // Clear loading state and show image
                                                if (imagePreview) {
                                                    imagePreview.innerHTML = '';
                                                    imagePreview.appendChild(img);
                                                    console.log('Image preview created successfully');
                                                } else {
                                                    console.error('Image preview container not found after load');
                                                }
                                                
                                                // Clean up download link after successful load
                                                if (document.body.contains(downloadLink)) {
                                                    document.body.removeChild(downloadLink);
                                                }
                                            };
                                            
                                            img.onerror = (error) => {
                                                console.error('Failed to load image:', error);
                                                console.error('Image details:', {
                                                    src: img.src.substring(0, 50) + '...',
                                                    type: targetType,
                                                    originalType: message.original_type,
                                                    metadataType: message.file_metadata?.type
                                                });
                                                
                                                imagePreview.innerHTML = `
                                                    <div class="encrypted-image-placeholder">
                                                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="currentColor" viewBox="0 0 16 16">
                                                            <path d="M6.002 5.5a1.5 1.5 0 1 1-3 0 1.5 1.5 0 0 1 3 0z"/>
                                                            <path d="M2.002 1a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V3a2 2 0 0 0-2-2h-12zm12 1a1 1 0 0 1 1 1v6.5l-3.777-1.947a.5.5 0 0 0-.577.093l-3.71 3.71-2.66-1.772a.5.5 0 0 0-.63.062L1.002 12V3a1 1 0 0 1 1-1h12z"/>
                                                        </svg>
                                                        <span>Failed to load encrypted image</span>
                                                        <button class="btn btn-sm btn-terminal" onclick="window.open('${downloadUrl}', '_blank')">
                                                            View Original
                                                        </button>
                                                    </div>`;
                                                
                                                // Clean up resources
                                                if (document.body.contains(downloadLink)) {
                                                    document.body.removeChild(downloadLink);
                                                }
                                                // Keep URL valid for the "View Original" button
                                            };
                                            
                                            // Configure image properties
                                            img.classList.add('embedded-image');
                                            img.alt = message.original_name || 'Decrypted image';
                                            img.setAttribute('data-original-type', targetType);
                                            img.setAttribute('crossorigin', 'anonymous');
                                            
                                            // Log and set src last to trigger loading
                                            console.log('Setting image src to trigger loading:', {
                                                url: downloadUrl.substring(0, 50) + '...',
                                                type: targetType
                                            });
                                            img.src = downloadUrl;
                                            
                                            console.log('Image element created with URL:', {
                                                alt: img.alt,
                                                classes: img.className,
                                                previewId: `image-${downloadId}`
                                            });
                                        } catch (previewError) {
                                            console.error('Error creating image preview:', previewError);
                                            console.error('Error details:', {
                                                error: previewError.message,
                                                stack: previewError.stack
                                            });
                                            imagePreview.innerHTML = 'Error displaying image';
                                            document.body.removeChild(downloadLink);
                                            URL.revokeObjectURL(downloadUrl);
                                        }
                                    } else {
                                        console.error('Image preview element not found:', `image-${downloadId}`);
                                        document.body.removeChild(downloadLink);
                                        URL.revokeObjectURL(downloadUrl);
                                    }
                                } else {
                                    // Handle non-image files with better feedback
                                    const downloadId = `file-${Date.now()}`;
                                    const fileInfo = document.createElement('div');
                                    fileInfo.className = 'file-attachment encrypted-file';
                                    fileInfo.innerHTML = `
                                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-file-earmark-lock" viewBox="0 0 16 16">
                                            <path d="M10 7v1.076c.54.166 1 .597 1 1.224v2.4c0 .816-.781 1.3-1.5 1.3h-3c-.719 0-1.5-.484-1.5-1.3V9.3c0-.627.46-1.058 1-1.224V7a2 2 0 1 1 4 0zM7 7v1h2V7a1 1 0 0 0-2 0z"/>
                                            <path d="M14 14V4.5L9.5 0H4a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2zM9.5 3A1.5 1.5 0 0 1 11 4.5h2V14a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1h5.5v2z"/>
                        </svg>
                        <span>${message.original_name || 'Encrypted File'}</span>
                        <button class="btn btn-sm btn-terminal encrypted-download-btn" onclick="window.open('${downloadUrl}', '_blank')">
                            Download Encrypted File
                        </button>`;
                                    
                                    const container = document.getElementById(downloadId);
                                    if (container) {
                                        container.appendChild(fileInfo);
                                    }
                                    
                                    // Clean up download link after a delay
                                    setTimeout(() => {
                                        if (document.body.contains(downloadLink)) {
                                            document.body.removeChild(downloadLink);
                                        }
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