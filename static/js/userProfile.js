// Helper functions defined first
function formatDate(dateString) {
  if (!dateString) return "Not available";
  const date = new Date(dateString);
  return date.toLocaleDateString("en-US", {
    year: "numeric",
    month: "long",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function safeSetTextContent(elementId, text) {
  const element = document.getElementById(elementId);
  if (element) {
    element.textContent = text || "";
  }
}

function safeSetSrc(elementId, src) {
  const element = document.getElementById(elementId);
  if (element) {
    element.src = src || "/static/images/default-avatar.png";
  }
}

function updateThemePreview(color) {
  document.documentElement.style.setProperty("--primary-color", color);
  document.documentElement.style.setProperty(
    "--primary-transparent",
    `${color}1A`,
  );
  document.documentElement.style.setProperty(
    "--primary-transparent-hover",
    `${color}26`,
  );
}

function updateProfileBanner(color) {
  const banner = document.getElementById("modalBanner");
  if (banner) {
    banner.style.backgroundColor = color;
  }
}

// Global variables
let profileModal = null;
let currentUserId = null;
let colorPicker = null;

// Define displayUserProfile as a global function
window.displayUserProfile = async function (userId) {
  console.log("displayUserProfile called for userId:", userId);

  if (!userId) {
    console.error("No user ID provided");
    return;
  }

  currentUserId = userId;

  // Show modal first with loading state
  if (profileModal) {
    profileModal.show();
  } else {
    console.error("Profile modal not initialized");
    return;
  }

  const content = document.querySelector(".profile-content");
  if (!content) {
    console.error("Profile content container not found");
    return;
  }

  // Show loading state
  content.innerHTML = `
        <div class="loading-spinner"></div>
        <div class="text-center mt-3">Loading profile...</div>
    `;

  try {
    console.log("Fetching user data...");
    const response = await fetch(`/api/user/by_id/${userId}`);

    if (!response.ok) {
      throw new Error(`Failed to fetch user data: ${response.status}`);
    }

    const userData = await response.json();
    console.log("User data received:", userData);

    if (!userData || typeof userData !== "object") {
      throw new Error("Invalid user data received");
    }

    // Prepare modal content
    const modalContent = `
            <div class="profile-banner" id="modalBanner">
                <div class="profile-header">
                    <div class="profile-avatar-container">
                        <img id="modalUserAvatar" src="${userData.avatar || "/static/images/default-avatar.png"}" 
                             alt="Profile Avatar" class="profile-avatar"
                             onerror="this.src='/static/images/default-avatar.png'">
                        <span id="modalPresenceIndicator" class="presence-indicator"></span>
                    </div>
                    <div class="profile-username-container">
                        <h2 id="modalUsername" class="profile-username">${userData.display_name || userData.username}</h2>
                        <div id="modalStatus" class="profile-status">${userData.status || "No status set"}</div>
                    </div>
                </div>
            </div>

            <div class="profile-section">
                <h3>about me</h3>
                <p id="modalBio" class="text-muted">${userData.bio || "No bio provided"}</p>
                <p id="modalLocation" class="text-muted">${userData.location || "Location not set"}</p>
            </div>

            <div class="profile-section">
                <h3>theme</h3>
                <div class="theme-section">
                    <div class="theme-customization">
                        <h4>Accent Color</h4>
                        <input type="color" id="accentColorPicker" class="color-picker" value="${userData.accent_color || "#5865F2"}">
                    </div>
                    <div class="theme-preview">
                        <div class="terminal-decoration">
                            <div class="terminal-buttons">
                                <span class="terminal-button terminal-button-red"></span>
                                <span class="terminal-button terminal-button-yellow"></span>
                                <span class="terminal-button terminal-button-green"></span>
                            </div>
                            <span class="terminal-title">preview@terminal:~$</span>
                        </div>
                        <div class="preview-container">
                            <div class="preview-message preview-own">
                                <span class="preview-timestamp">12:00</span>
                                <span class="preview-username">You</span>
                                Preview of your messages
                            </div>
                            <div class="preview-message preview-other">
                                <span class="preview-timestamp">12:01</span>
                                <span class="preview-username">Other User</span>
                                Preview of other's messages
                            </div>
                            <div class="preview-input">
                                <span class="prompt">$</span>
                                <input type="text" class="preview-message-input" placeholder="Type a message...">
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="member-since">
                whois user
                <br>
                Member since <span id="modalJoinDate">${formatDate(userData.created_at)}</span>
                <br>
                Last seen <span id="modalLastSeen">${formatDate(userData.last_seen)}</span>
            </div>

            <div class="profile-actions">
                <button id="messageUserBtn" class="btn btn-terminal">Send Message</button>
                <button type="button" class="btn btn-terminal" data-bs-dismiss="modal">Close</button>
            </div>
        `;

    // Update modal content
    content.innerHTML = modalContent;

    // Initialize new color picker
    const picker = document.getElementById("accentColorPicker");
    if (picker) {
      picker.addEventListener("input", function (e) {
        const color = e.target.value;
        updateThemePreview(color);
        updateProfileBanner(color);
        
        // Save the color change to the server
        if (currentUserId) {
          fetch('/api/user/update_theme', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              user_id: currentUserId,
              accent_color: color
            })
          })
          .then(response => response.json())
          .then(data => {
            console.log('Theme updated successfully:', data);
          })
          .catch(error => {
            console.error('Error updating theme:', error);
          });
        }
      });

      // Set initial theme
      if (userData.accent_color) {
        updateThemePreview(userData.accent_color);
        updateProfileBanner(userData.accent_color);
      }
    }

    // Add loading complete class
    content.classList.add("loaded");

    console.log("Profile modal content updated successfully");
  } catch (error) {
    console.error("Error in displayUserProfile:", error);
    content.innerHTML = `
            <div class="alert alert-danger">
                <strong>Error loading profile:</strong><br>
                ${error.message || "Failed to load user profile. Please try again."}
            </div>
        `;
  }
};

// Wait for the DOM to be fully loaded
document.addEventListener("DOMContentLoaded", function () {
  console.log("Initializing profile modal handlers...");

  // Initialize Bootstrap modal
  const modalElement = document.getElementById("userProfileModal");
  if (modalElement) {
    profileModal = new bootstrap.Modal(modalElement);
    console.log("Profile modal initialized");
  } else {
    console.error("Failed to find profile modal element");
  }

  // Initialize color picker
  colorPicker = document.getElementById("accentColorPicker");
  if (colorPicker) {
    colorPicker.addEventListener("input", function (e) {
      const color = e.target.value;
      console.log("Color picker changed:", color);
      updateThemePreview(color);
      updateProfileBanner(color);
    });
    console.log("Color picker initialized");
  } else {
    console.warn("Color picker element not found");
  }

  // Event delegation for user profile clicks
  document.body.addEventListener("click", async function (event) {
    const userElement = event.target.closest("[data-user-id]");
    if (userElement) {
      event.preventDefault();
      const userId = userElement.dataset.userId;
      console.log("Profile click detected for user:", userId);
      try {
        await window.displayUserProfile(userId);
      } catch (error) {
        console.error("Error displaying user profile:", error);
        const content = document.querySelector(".profile-content");
        if (content) {
          content.innerHTML = `
                        <div class="alert alert-danger">
                            <strong>Error loading profile:</strong><br>
                            ${error.message || "Failed to load user profile"}
                        </div>
                    `;
        }
      }
    }
  });

  // Initialize message button handler
  const messageUserBtn = document.getElementById("messageUserBtn");
  if (messageUserBtn) {
    messageUserBtn.addEventListener("click", async function () {
      if (currentUserId && typeof socket !== "undefined") {
        console.log("Starting DM with user:", currentUserId);
        
        // Emit socket event to start a direct message
        socket.emit("start_direct_message", { target_user_id: currentUserId });
        
        // Get the username for the target user
        try {
          const response = await fetch(`/api/user/by_id/${currentUserId}`);
          const userData = await response.json();
          
          // Add @ prefix to username in message input
          const messageInput = document.getElementById("messageInput");
          if (messageInput) {
            messageInput.value = `@${userData.username} `;
            messageInput.focus();
          }
        } catch (error) {
          console.error("Error fetching user data:", error);
        }
        
        // Close the modal
        profileModal.hide();
      } else {
        console.warn("Cannot start DM - missing userId or socket");
      }
    });
    console.log("Message button handler initialized");
  }

  // Modal cleanup handler
  if (modalElement) {
    modalElement.addEventListener("hidden.bs.modal", function () {
      console.log("Modal hidden - cleaning up");
      currentUserId = null;
      const content = modalElement.querySelector(".profile-content");
      if (content) {
        content.innerHTML = '<div class="loading-spinner"></div>';
      }
    });

    modalElement.addEventListener("show.bs.modal", function () {
      console.log("Modal showing - preparing content");
    });
  }

  console.log("Profile modal setup complete");
});
