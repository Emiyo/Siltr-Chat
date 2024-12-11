// Chat panel functionality
class ChatPanel {
    constructor(socket) {
        this.socket = socket;
        this.messageForm = document.getElementById('messageForm');
        this.messageInput = document.getElementById('messageInput');
        this.messageContainer = document.getElementById('messageContainer');
        this.attachButton = document.getElementById('attachButton');
        this.messageHistory = [];
        this.historyIndex = -1;
        this.channelPanel = null; // Will be set after initialization
        this.initializeEventListeners();
        this.setupFileHandling();
    }

    setChannelPanel(channelPanel) {
        this.channelPanel = channelPanel;
    }

    initializeEventListeners() {
        this.messageForm.addEventListener('submit', this.handleMessageSubmit.bind(this));
        this.messageInput.addEventListener('keydown', this.handleCommandHistory.bind(this));
        
        this.socket.on('new_message', (message) => {
            this.addMessage(message);
            this.scrollToBottom();
        });

        this.socket.on('message_history', (data) => {
            this.messageContainer.innerHTML = '';
            data.messages.forEach(message => this.addMessage(message));
            this.scrollToBottom();
        });
    }

    setupFileHandling() {
        const fileInput = document.createElement('input');
        fileInput.type = 'file';
        fileInput.style.display = 'none';
        document.body.appendChild(fileInput);

        this.attachButton.addEventListener('click', () => fileInput.click());
        fileInput.addEventListener('change', this.handleFileUpload.bind(this));
    }

    async handleMessageSubmit(e) {
        e.preventDefault();
        const message = this.messageInput.value.trim();
        if (!message) return;

        // Handle commands
        if (message.startsWith('/')) {
            this.socket.emit('message', {
                text: message,
                channel_id: this.channelPanel.getCurrentChannel()
            });
            this.messageHistory.push(message);
            this.historyIndex = this.messageHistory.length;
            this.messageInput.value = '';
            return;
        }

        // Handle private messages
        if (message.startsWith('@')) {
            const spaceIndex = message.indexOf(' ');
            if (spaceIndex > 1) {
                const recipient = message.substring(1, spaceIndex);
                const privateMessage = message.substring(spaceIndex + 1);
                this.socket.emit('private_message', {
                    recipient: recipient,
                    text: privateMessage
                });
            }
            this.messageHistory.push(message);
            this.historyIndex = this.messageHistory.length;
            this.messageInput.value = '';
            return;
        }

        // Handle regular messages
        const currentChannel = this.channelPanel.getCurrentChannel();
        if (!currentChannel) {
            this.addMessage({
                type: 'system',
                text: 'Please select a channel first',
                timestamp: new Date().toISOString()
            });
            return;
        }

        this.socket.emit('message', {
            text: message,
            channel_id: currentChannel
        });
        
        this.messageHistory.push(message);
        this.historyIndex = this.messageHistory.length;
        this.messageInput.value = '';
    }

    handleCommandHistory(e) {
        if (e.key === 'ArrowUp') {
            e.preventDefault();
            if (this.historyIndex > 0) {
                this.historyIndex--;
                this.messageInput.value = this.messageHistory[this.historyIndex];
            }
        } else if (e.key === 'ArrowDown') {
            e.preventDefault();
            if (this.historyIndex < this.messageHistory.length - 1) {
                this.historyIndex++;
                this.messageInput.value = this.messageHistory[this.historyIndex];
            } else {
                this.historyIndex = this.messageHistory.length;
                this.messageInput.value = '';
            }
        }
    }

    async handleFileUpload(e) {
        const file = e.target.files[0];
        if (!file) return;

        const currentChannel = this.channelPanel.getCurrentChannel();
        if (!currentChannel) {
            this.addMessage({
                type: 'system',
                text: 'Please select a channel before uploading files',
                timestamp: new Date().toISOString()
            });
            e.target.value = '';
            return;
        }

        try {
            const formData = new FormData();
            formData.append('file', file);
            formData.append('channel_id', currentChannel);

            const response = await fetch('/upload', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) throw new Error(`Upload failed: ${response.statusText}`);

            const data = await response.json();
            this.socket.emit('message', {
                text: `Shared a file: ${file.name}`,
                file_url: data.file_url,
                channel_id: currentChannel
            });
        } catch (error) {
            console.error('Error uploading file:', error);
            this.addMessage({
                type: 'system',
                text: 'Failed to upload file: ' + error.message,
                timestamp: new Date().toISOString()
            });
        }
        e.target.value = '';
    }

    addMessage(message) {
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${message.type || 'user'}`;
        const timestamp = new Date(message.timestamp).toLocaleTimeString();
        
        let content = '';
        if (message.type === 'system') {
            content = `<div class="system-message">${message.text}</div>`;
        } else {
            content = `
                <div class="message-header">
                    <span class="username">${message.username || 'Anonymous'}</span>
                    <span class="timestamp">${timestamp}</span>
                </div>
                <div class="message-content">${message.text}</div>
            `;
        }
        
        messageDiv.innerHTML = content;
        this.messageContainer.appendChild(messageDiv);
    }

    scrollToBottom() {
        this.messageContainer.scrollTop = this.messageContainer.scrollHeight;
    }
}

export default ChatPanel;
