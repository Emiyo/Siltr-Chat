// Chat functionality
let socket;
let currentChannel = null;
let categories = [];
let messageContainer;
let user_id;
let username;

document.addEventListener("DOMContentLoaded", () => {
  messageContainer = document.getElementById("messageContainer");
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
      socket.emit("message", {
        text: message,
        channel_id: currentChannel,
        parent_id: replyToId || null,
      });
      messageInput.value = "";
      messageInput.removeAttribute("data-reply-to");
    }
  });

  // Message handling
  socket.on("message", (data) => {
    addMessage(data);
    scrollToBottom();
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

    categoryList.innerHTML = categories
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
      messageDiv.innerHTML = `
                <div class="message-timestamp">${timestamp}</div>
                ${messageContent}`;
    } else if (message.type === "private") {
      messageDiv.className = "message message-private";
      const isOwnMessage = message.user_id === user_id;
      const otherUser = isOwnMessage
        ? message.receiver_username
        : message.user.username;
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
      messageDiv.innerHTML = `${messageHeader}${messageContent}`;

      // Only add reply button for regular messages
      if (!message.type) {
        messageDiv.innerHTML += `
                <div class="message-actions">
                    <button class="btn btn-sm btn-terminal reply-btn" onclick="replyToMessage(${message.id}, '${message.user ? message.user.username : "Unknown"}')">
                        <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" fill="currentColor" class="bi bi-reply" viewBox="0 0 16 16">
                            <path d="M6.598 5.013a.144.144 0 0 1 .202.134V6.3a.5.5 0 0 0 .5.5c.667 0 2.013.005 3.3.822.984.624 1.99 1.76 2.595 3.876-1.02-.983-2.185-1.516-3.205-1.799a8.74 8.74 0 0 0-1.921-.306 7.404 7.404 0 0 0-.798.008h-.013l-.005.001h-.001L7.3 9.9l-.05-.498a.5.5 0 0 0-.45.498v1.153c0 .108-.11.176-.202.134L2.614 8.254a.503.503 0 0 0-.042-.028.147.147 0 0 1 0-.252.499.499 0 0 0 .042-.028l3.984-2.933zM7.8 10.386c.068 0 .143.003.223.006.434.02 1.034.086 1.7.271 1.326.368 2.896 1.202 3.94 3.08a.5.5 0 0 0 .933-.305c-.464-3.71-1.886-5.662-3.46-6.66-1.245-.79-2.527-.942-3.336-.971v-.66a1.144 1.144 0 0 0-1.767-.96l-3.994 2.94a1.147 1.147 0 0 0 0 1.946l3.994 2.94a1.144 1.144 0 0 0 1.767-.96v-.667z"/>
                        </svg>
                        Reply
                    </button>
                </div>`;
      }
    }

    if (message.parent_id) {
      messageDiv.classList.add("threaded-message");
    }

    messageContainer.appendChild(messageDiv);
  }

  function replyToMessage(messageId, username) {
    const messageInput = document.getElementById("messageInput");
    if (messageInput) {
      messageInput.value = `@${username} `;
      messageInput.setAttribute("data-reply-to", messageId);
      messageInput.focus();
    }
  }

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
                    <div class="user-item" onclick="window.displayUserProfile(${user.id})">
                        <div class="user-info">
                            <span class="username online">
                                ${user.display_name || user.username}
                            </span>
                            ${user.status ? `<div class="user-status">${user.status}</div>` : ""}
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
                    <div class="user-item" onclick="window.displayUserProfile(${user.id})">
                        <div class="user-info">
                            <span class="username offline">
                                ${user.display_name || user.username}
                            </span>
                            ${user.status ? `<div class="user-status">${user.status}</div>` : ""}
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
