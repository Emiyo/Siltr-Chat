// Channel panel functionality
class ChannelPanel {
    constructor(socket, messageContainer) {
        this.socket = socket;
        this.messageContainer = messageContainer;
        this.categoryList = document.getElementById('categoryList');
        this.currentChannel = null;
        this.categories = [];
        this.initializeEventListeners();
    }

    initializeEventListeners() {
        this.socket.on('categories_list', (data) => {
            if (data && data.categories) {
                this.categories = data.categories;
                this.updateCategoryList();
            }
        });

        this.socket.on('category_created', (category) => {
            this.categories.push(category);
            this.updateCategoryList();
        });

        this.socket.on('channel_created', (channel) => {
            const category = this.categories.find(c => c.id === channel.category_id);
            if (category) {
                if (!category.channels) category.channels = [];
                category.channels.push(channel);
                this.updateCategoryList();
            }
        });
    }

    updateCategoryList() {
        if (!this.categoryList || !Array.isArray(this.categories)) {
            console.error('Invalid categories data or missing categoryList element');
            return;
        }
        
        console.log('Updating category list with:', this.categories);
        
        this.categoryList.innerHTML = this.categories.map(group => {
            const channels = group.channels || [];
            const groupIcon = group.name.toLowerCase() === 'text' ? '#' : 
                            group.name.toLowerCase() === 'voice' ? '🔊' : 
                            group.name.toLowerCase() === 'announcement' ? '📢' : '💬';
            
            return `
                <div class="category-item">
                    <div class="category-header">
                        <span class="category-toggle">▼</span>
                        ${groupIcon} ${group.name}
                    </div>
                    <div class="channel-list" style="display: block;">
                        ${channels.map(channel => `
                            <div class="channel-item ${channel.id === this.currentChannel ? 'active' : ''}" 
                                 data-channel-id="${channel.id}"
                                 data-channel-type="${channel.type || 'text'}">
                                ${channel.type === 'voice' ? '🔊' : '#'} ${channel.name}
                                ${channel.description ? `<div class="channel-description">${channel.description}</div>` : ''}
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        }).join('');

        this.attachEventHandlers();
    }

    attachEventHandlers() {
        // Attach channel click handlers
        document.querySelectorAll('.channel-item').forEach(item => {
            item.addEventListener('click', () => {
                const channelId = parseInt(item.dataset.channelId);
                this.switchChannel(channelId, item);
            });
        });

        // Attach category toggle handlers
        document.querySelectorAll('.category-header').forEach(header => {
            header.addEventListener('click', () => {
                const channelList = header.nextElementSibling;
                const toggle = header.querySelector('.category-toggle');
                channelList.style.display = channelList.style.display === 'none' ? 'block' : 'none';
                toggle.textContent = channelList.style.display === 'none' ? '▶' : '▼';
            });
        });
    }

    switchChannel(channelId, channelElement) {
        if (this.currentChannel !== channelId) {
            if (this.currentChannel) {
                this.socket.emit('leave_channel', { channel_id: this.currentChannel });
            }
            this.currentChannel = channelId;
            this.messageContainer.innerHTML = '';
            this.socket.emit('system_message', {
                type: 'system',
                text: `Joined channel #${channelElement.textContent.trim()}`,
                timestamp: new Date().toISOString()
            });
            this.socket.emit('join_channel', { channel_id: channelId });
            document.querySelectorAll('.channel-item').forEach(ch => 
                ch.classList.toggle('active', ch.dataset.channelId === String(channelId))
            );
        }
    }

    getCurrentChannel() {
        return this.currentChannel;
    }
}

export default ChannelPanel;
