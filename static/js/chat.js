// Chat functionality
let socket;
let currentChannel = null;
let categories = [];
let messageContainer;
let user_id;
let username;

document.addEventListener("DOMContentLoaded", () => {
  messageContainer = document.getElementById("messageContainer");
// Track active conversations
let activeConversations = [];

// Update active conversations when receiving or sending a DM
function updateActiveConversations(message) {
  const otherUser = message.sender_id === user_id ? message.recipient : message.sender;
  if (!otherUser) return; // Skip if no valid user object
  
  // Find existing conversation
  const existingIndex = activeConversations.findIndex(u => u.id === otherUser.id);
  
  if (existingIndex === -1) {
    // New conversation
    activeConversations.push({
      id: otherUser.id,
      username: otherUser.username || message.recipient_username,
      display_name: otherUser.display_name || otherUser.username || message.recipient_username,
      last_seen: otherUser.last_seen,
      unread_count: message.sender_id === user_id ? 0 : 1
    });
  } else {
    // Update existing conversation
    const existing = activeConversations[existingIndex];
    if (message.sender_id !== user_id) {
      existing.unread_count = (existing.unread_count || 0) + 1;
    }
    existing.last_seen = otherUser.last_seen;
  }
  
  // Always update the category list to refresh UI
  updateCategoryList();
}
  const messageForm = document.getElementById("messageForm");
  const messageInput = document.getElementById("messageInput");

  // Get user info from data attributes
  const userElement = document.getElementById("user-info");
  if (userElement) {
    user_id = parseInt(userElement.dataset.userId);
    username = userElement.dataset.username;
  }

  // Initialize Socket.IO connection
  socket = io();

  socket.on("connect", () => {
    console.log("Connected to server");
    socket.emit("join", { username });
  });

  messageForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const message = messageInput.value.trim();
    if (message) {
      const replyToId = messageInput.getAttribute("data-reply-to");
      const recipientId = messageInput.getAttribute("data-recipient-id");
      
      // Check if it's a direct message
      if (recipientId) {
        const parsedRecipientId = parseInt(recipientId);
        const dmData = {
          text: message,
          recipient_id: parsedRecipientId,
        };
        
        // Update active conversations before sending
        const recipient = activeConversations.find(u => u.id === parsedRecipientId);
        if (!recipient) {
          // If recipient not in active conversations, fetch user from user list
          const allUsers = document.querySelectorAll('.user-item');
          for (const userEl of allUsers) {
            if (userEl.querySelector('.user-actions button').onclick.toString().includes(parsedRecipientId)) {
              const username = userEl.querySelector('.username').textContent.trim();
              activeConversations.push({
                id: parsedRecipientId,
                username: username,
                display_name: username
              });
              break;
            }
          }
        }
        
        // Update conversations list
        updateActiveConversations({
          content: message,
          sender_id: user_id,
          recipient_id: parsedRecipientId,
          recipient: recipient || activeConversations.find(u => u.id === parsedRecipientId)
        });
        
        socket.emit("direct_message", dmData);
        messageInput.removeAttribute("data-recipient-id");
        messageInput.value = "";
      } else {
        socket.emit("message", {
          text: message,
          channel_id: currentChannel,
          parent_id: replyToId || null,
        });
        messageInput.removeAttribute("data-reply-to");
        messageInput.value = "";
      }
    }
  });

  // Message handling
  socket.on("message", (data) => {
    addMessage(data);
    scrollToBottom();
  });

  // Typing indicator handling
  let typingTimer;
  const TYPING_TIMER_LENGTH = 3000; // How long to wait after last keystroke before stopping typing indicator

  function sendTypingIndicator(isTyping) {
    const recipientId = messageInput.getAttribute('data-recipient-id');
    if (recipientId) {
      socket.emit('typing_indicator', {
        recipient_id: recipientId,
        is_typing: isTyping
      });
    }
  }

  socket.on("user_typing", (data) => {
    const typingIndicator = document.getElementById(`typing-${data.user_id}`);
    if (data.is_typing) {
      if (!typingIndicator) {
        const typingDiv = document.createElement('div');
        typingDiv.id = `typing-${data.user_id}`;
        typingDiv.className = 'typing-indicator';
        typingDiv.innerHTML = `${data.username} is typing...`;
        messageContainer.appendChild(typingDiv);
        scrollToBottom();
      }
    } else if (typingIndicator) {
      typingIndicator.remove();
    }
  });

  // Add typing detection to message input
  messageInput.addEventListener('input', () => {
    if (!messageInput.getAttribute('data-recipient-id')) return;
    
    sendTypingIndicator(true);
    clearTimeout(typingTimer);
    typingTimer = setTimeout(() => {
      sendTypingIndicator(false);
    }, TYPING_TIMER_LENGTH);
  });

  socket.on("direct_message", (data) => {
    addMessage({
      ...data,
      type: "private"
    });
    scrollToBottom();
    
    // Update active conversations list
    updateActiveConversations(data);
    
    // Mark message as read if we're the recipient and in the DM view
    if (data.recipient_id === user_id && messageInput.getAttribute('data-recipient-id') === String(data.sender_id)) {
      socket.emit('mark_dm_read', { message_id: data.id });
    }
  });

  socket.on("user_list", (data) => {
    updateUserList(data.users);
  });

  // Categories and Channels
  socket.on("categories_list", (data) => {
    console.log("Received categories:", data);
    if (data && data.categories) {
      categories = data.categories;
      updateCategoryList();
    } else {
      console.error("Invalid categories data received:", data);
    }
  });

  socket.on("category_created", (category) => {
    categories.push(category);
    updateCategoryList();
  });

  socket.on("channel_created", (channel) => {
    const category = categories.find((c) => c.id === channel.category_id);
    if (category) {
      if (!category.channels) category.channels = [];
      category.channels.push(channel);
      updateCategoryList();
    }
  });

  socket.on("channel_history", (data) => {
    if (data.channel_id === currentChannel) {
      messageContainer.innerHTML = "";
      data.messages.forEach((message) => addMessage(message));
      scrollToBottom();
    }
  });

  socket.on("clear_chat", () => {
    messageContainer.innerHTML = "";
    addMessage({
      type: "system",
      text: "Chat cleared",
      timestamp: new Date().toISOString(),
    });
  });

  // Helper Functions
  function updateCategoryList() {
    const categoryList = document.getElementById("categoryList");
    if (!categoryList) {
      console.error("Category list element not found");
      return;
    }

    if (!Array.isArray(categories)) {
      console.error("Categories is not an array:", categories);
      return;
    }

    // First add Direct Messages section
    const dmSection = `
      <div class="category-item">
        <div class="category-header">
          <span class="category-toggle">▼</span>
          Direct Messages
        </div>
        <div class="channel-list" style="display: block;" id="dm-list">
          ${activeConversations.map(user => `
            <div class="channel-item ${user.id === parseInt(messageInput.getAttribute('data-recipient-id')) ? "active" : ""}"
                 onclick="startDirectMessage(${user.id}, '${user.username}')">
              <span class="user-status-indicator ${user.last_seen && new Date(user.last_seen) > new Date(Date.now() - 5 * 60 * 1000) ? 'online' : 'offline'}"></span>
              ${user.display_name || user.username}
              ${user.unread_count ? `<span class="unread-count">${user.unread_count}</span>` : ''}
            </div>
          `).join("")}
        </div>
      </div>
    `;

    // Then add regular categories
    const categoriesHTML = categories
      .map((category) => {
        const channels = Array.isArray(category.channels)
          ? category.channels
          : [];
        return `
          <div class="category-item">
            <div class="category-header">
              <span class="category-toggle">▼</span>
              ${category.name || "Unnamed Category"}
            </div>
            <div class="channel-list" style="display: block;">
              ${channels
                .map(
                  (channel) => `
                  <div class="channel-item ${channel.id === currentChannel ? "active" : ""}" 
                       data-channel-id="${channel.id}">
                    ${channel.is_private ? "🔒" : "#"} ${channel.name || "Unnamed Channel"}
                  </div>
                `,
                )
                .join("")}
            </div>
          </div>
        `;
      })
      .join("");

    categoryList.innerHTML = dmSection + categoriesHTML;

    // Add event listeners
    document.querySelectorAll(".category-header").forEach((header) => {
      header.addEventListener("click", () => {
        const channelList = header.nextElementSibling;
        const toggle = header.querySelector(".category-toggle");
        channelList.style.display =
          channelList.style.display === "none" ? "block" : "none";
        toggle.textContent = channelList.style.display === "none" ? "▶" : "▼";
      });
    });

    document.querySelectorAll(".channel-item").forEach((item) => {
      item.addEventListener("click", () => {
        const channelId = parseInt(item.dataset.channelId);
        if (currentChannel !== channelId) {
          if (currentChannel) {
            socket.emit("leave_channel", { channel_id: currentChannel });
          }
          currentChannel = channelId;
          messageContainer.innerHTML = "";
          addMessage({
            type: "system",
            text: `Joined channel #${item.textContent.trim()}`,
            timestamp: new Date().toISOString(),
          });
          socket.emit("join_channel", { channel_id: channelId });
          document
            .querySelectorAll(".channel-item")
            .forEach((ch) =>
              ch.classList.toggle(
                "active",
                ch.dataset.channelId === String(channelId),
              ),
            );
        }
      });
    });
  }

  async function addMessage(message) {
    const messageDiv = document.createElement("div");
    const timestamp = new Date(message.timestamp).toLocaleTimeString();
    let messageContent = message.content || message.text;
    let messageHeader = "";

    if (message.type === "system") {
      messageDiv.className = "message message-system";
      messageDiv.innerHTML = `<span class="system-message-text"><span class="message-timestamp">${timestamp}</span> ${messageContent}</span>`;
    } else if (message.type === "private") {
      messageDiv.className = "message message-private";
      const isOwnMessage = message.sender_id === user_id;
      const otherUser = isOwnMessage ? 
        (message.recipient ? message.recipient.username : 'Unknown') : 
        (message.sender ? message.sender.username : 'Unknown');
      
      messageHeader = `
                <div class="message-timestamp">
                    <span class="message-username">${isOwnMessage ? username : otherUser}</span> • ${timestamp}
                </div>`;
      messageDiv.innerHTML = `
                ${messageHeader}
                <div class="message-private-indicator">🔒 Private message ${isOwnMessage ? "to" : "from"} ${otherUser}</div>
                ${messageContent}`;
    } else {
      const isOwnMessage = message.user_id === user_id;
      messageDiv.className = `message ${isOwnMessage ? "message-own" : "message-other"}`;
      messageHeader = isOwnMessage
        ? `<div class="message-timestamp">${timestamp}</div>`
        : `<div class="message-timestamp">
                    <span class="message-username">${message.user ? message.user.username : "Unknown"}</span> • ${timestamp}
                </div>`;
      
      let threadPreview = '';
      if (message.replies && message.replies.length > 0) {
        const replyCount = message.replies.length;
        const lastReply = message.replies[message.replies.length - 1];
        threadPreview = `
          <div class="thread-container">
            <div class="thread-header">
              <span class="thread-count">${replyCount} ${replyCount === 1 ? 'reply' : 'replies'}</span>
              Latest reply from ${lastReply.user.username}
            </div>
            <div class="thread-preview">${lastReply.content}</div>
          </div>
        `;
      }
      
      messageDiv.innerHTML = `
          ${messageHeader}
          <div class="message-content">${messageContent}</div>
          ${threadPreview}
      `;

      // Add reply button for all messages except system messages
      if (message.type !== 'system') {
        messageDiv.innerHTML = `
          ${messageHeader}
          <div class="message-content">${messageContent}</div>
          ${threadPreview}
          <div class="message-actions">
            <button class="btn btn-sm btn-terminal reply-btn" onclick="window.replyToMessage(${message.id}, '${message.user ? message.user.username : "Unknown"}')">
              <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" fill="currentColor" class="bi bi-reply" viewBox="0 0 16 16">
                <path d="M6.598 5.013a.144.144 0 0 1 .202.134V6.3a.5.5 0 0 0 .5.5c.667 0 2.013.005 3.3.822.984.624 1.99 1.76 2.595 3.876-1.02-.983-2.185-1.516-3.205-1.799a8.74 8.74 0 0 0-1.921-.306 7.404 7.404 0 0 0-.798.008h-.013l-.005.001h-.001L7.3 9.9l-.05-.498a.5.5 0 0 0-.45.498v1.153c0 .108-.11.176-.202.134L2.614 8.254a.503.503 0 0 0-.042-.028.147.147 0 0 1 0-.252.499.499 0 0 0 .042-.028l3.984-2.933zM7.8 10.386c.068 0 .143.003.223.006.434.02 1.034.086 1.7.271 1.326.368 2.896 1.202 3.94 3.08a.5.5 0 0 0 .933-.305c-.464-3.71-1.886-5.662-3.46-6.66-1.245-.79-2.527-.942-3.336-.971v-.66a1.144 1.144 0 0 0-1.767-.96l-3.994 2.94a1.147 1.147 0 0 0 0 1.946l3.994 2.94a1.144 1.144 0 0 0 1.767-.96v-.667z"/>
              </svg>
              Reply
            </button>
          </div>`;
      } else {
        messageDiv.innerHTML = `
          ${messageHeader}
          <div class="message-content">${messageContent}</div>
          ${threadPreview}`;
      }
    }

    if (message.parent_id) {
      messageDiv.classList.add("threaded-message");
    }

    messageContainer.appendChild(messageDiv);
  }

  // Make replyToMessage globally accessible
  window.replyToMessage = function(messageId, username) {
    const messageInput = document.getElementById("messageInput");
    if (messageInput) {
      messageInput.value = `@${username} `;
      messageInput.setAttribute("data-reply-to", messageId);
      messageInput.focus();
    }
  };

  window.startDirectMessage = function(userId, username) {
    const messageInput = document.getElementById("messageInput");
    messageInput.setAttribute("data-recipient-id", userId);
    messageInput.value = `@${username} `;
    messageInput.focus();
    
    // Load DM history when starting a conversation
    socket.emit('get_dm_history', { user_id: userId });
    
    // Show loading indicator
    const loadingMessage = document.createElement('div');
    loadingMessage.className = 'message message-system';
    loadingMessage.innerHTML = '<span class="system-message-text">Loading message history...</span>';
    messageContainer.appendChild(loadingMessage);
    
    // Clear current channel to show we're in DM mode
    currentChannel = null;
    document.querySelectorAll('.channel-item').forEach(ch => ch.classList.remove('active'));
    
    // Add DM indicator in message container
    const dmIndicator = document.createElement('div');
    dmIndicator.className = 'dm-indicator';
    dmIndicator.innerHTML = `Direct Message with ${username}`;
    messageContainer.innerHTML = '';
    messageContainer.appendChild(dmIndicator);
  };

  // Handle DM history
  socket.on('dm_history', (data) => {
    // Clear message container except for DM indicator
    const dmIndicator = messageContainer.querySelector('.dm-indicator');
    messageContainer.innerHTML = '';
    if (dmIndicator) messageContainer.appendChild(dmIndicator);
    
    // Add messages
    data.messages.forEach(message => {
      addMessage({
        ...message,
        type: 'private'
      });
      // Update active conversations for each message
      updateActiveConversations(message);
    });
    scrollToBottom();
  });

  // Handle notifications
  socket.on('notification', (data) => {
    if (data.type === 'new_dm') {
      // Create notification
      const notification = document.createElement('div');
      notification.className = 'notification notification-dm';
      notification.innerHTML = `
        <div class="notification-content">
          <strong>${data.sender}</strong>: ${data.message}
        </div>
      `;
      
      // Add to DOM
      const notificationContainer = document.getElementById('notificationContainer') || 
        document.createElement('div');
      if (!document.getElementById('notificationContainer')) {
        notificationContainer.id = 'notificationContainer';
        document.body.appendChild(notificationContainer);
      }
      
      notificationContainer.appendChild(notification);
      
      // Remove after 5 seconds
      setTimeout(() => {
        notification.classList.add('fade-out');
        setTimeout(() => notification.remove(), 300);
      }, 5000);
    }
  });

  function updateUserList(users) {
    const userList = document.getElementById("userList");
    if (!userList || !Array.isArray(users)) {
      console.error("Invalid user list or users data");
      return;
    }

    // Sort users: online users first (last_seen within last 5 minutes), then offline
    const now = new Date();
    const fiveMinutesAgo = new Date(now - 5 * 60 * 1000);

    const onlineUsers = [];
    const offlineUsers = [];

    users.forEach((user) => {
      if (!user || !user.username) return;
      const isOnline =
        user.last_seen && new Date(user.last_seen) > fiveMinutesAgo;
      (isOnline ? onlineUsers : offlineUsers).push(user);
    });

    // Sort each group alphabetically
    const sortByName = (a, b) =>
      (a.display_name || a.username).localeCompare(
        b.display_name || b.username,
      );
    onlineUsers.sort(sortByName);
    offlineUsers.sort(sortByName);

    // Generate HTML with separators
    userList.innerHTML = `
            <div class="user-section">
                <div class="user-section-header">Online — ${onlineUsers.length}</div>
                ${onlineUsers
                  .map(
                    (user) => `
                    <div class="user-item">
                        <div class="user-info" onclick="window.displayUserProfile(${user.id})">
                            <span class="username online">
                                ${user.display_name || user.username}
                            </span>
                            ${user.status ? `<div class="user-status">${user.status}</div>` : ""}
                        </div>
                        <div class="user-actions">
                            <button class="btn btn-sm btn-terminal" onclick="startDirectMessage(${user.id}, '${user.username}')">
                                Message
                            </button>
                        </div>
                    </div>
                `,
                  )
                  .join("")}
            </div>
            <div class="user-section">
                <div class="user-section-header">Offline — ${offlineUsers.length}</div>
                ${offlineUsers
                  .map(
                    (user) => `
                    <div class="user-item">
                        <div class="user-info" onclick="window.displayUserProfile(${user.id})">
                            <span class="username offline">
                                ${user.display_name || user.username}
                            </span>
                            ${user.status ? `<div class="user-status">${user.status}</div>` : ""}
                        </div>
                        <div class="user-actions">
                            <button class="btn btn-sm btn-terminal" onclick="startDirectMessage(${user.id}, '${user.username}')">
                                Message
                            </button>
                        </div>
                    </div>
                `,
                  )
                  .join("")}
            </div>
        `;
  }

  // Navigation bar event listeners
  const profileBtn = document.querySelector(".profile-btn");
  if (profileBtn) {
    profileBtn.addEventListener("click", () => {
      window.displayUserProfile("current");
    });

    profileBtn.addEventListener("mouseover", () => {
      window.displayUserProfile("current");
    });
  }
});

// Function to scroll chat to bottom
function scrollToBottom() {
  if (messageContainer) {
    messageContainer.scrollTop = messageContainer.scrollHeight;
  }
}
