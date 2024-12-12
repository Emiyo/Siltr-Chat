// Window control functionality
class TerminalWindow {
  constructor(container) {
    this.container = container;
    this.originalDimensions = {
      width: container.offsetWidth + 'px',
      height: container.offsetHeight + 'px',
      position: window.getComputedStyle(container).position,
      top: window.getComputedStyle(container).top,
      left: window.getComputedStyle(container).left,
      right: window.getComputedStyle(container).right,
      bottom: window.getComputedStyle(container).bottom,
      zIndex: window.getComputedStyle(container).zIndex
    };
    this.isMinimized = false;
    this.isMaximized = false;
    this.isDragging = false;
    this.dragOffset = { x: 0, y: 0 };
    this.setupControls();
    this.setupDragging();
    this.saveInitialContent();
  }

  setupControls() {
    const buttons = this.container.querySelector('.terminal-buttons');
    if (!buttons) return;

    // Close button (red)
    const closeBtn = buttons.querySelector('.terminal-button-red');
    if (closeBtn) {
      closeBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        this.close();
      });
    }

    // Minimize button (yellow)
    const minimizeBtn = buttons.querySelector('.terminal-button-yellow');
    if (minimizeBtn) {
      minimizeBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        this.minimize();
      });
    }

    // Maximize button (green)
    const maximizeBtn = buttons.querySelector('.terminal-button-green');
    if (maximizeBtn) {
      maximizeBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        this.maximize();
      });
    }

    // Double click header to maximize
    const header = this.container.querySelector('.terminal-header');
    if (header) {
      header.addEventListener('dblclick', (e) => {
        e.stopPropagation();
        this.maximize();
      });
    }
  }

  setupDragging() {
    const header = this.container.querySelector('.terminal-header');
    if (!header) return;

    header.addEventListener('mousedown', (e) => {
      // Don't start dragging if clicking buttons or if window is maximized
      if (e.target.closest('.terminal-buttons') || this.isMaximized) return;

      this.isDragging = true;
      const rect = this.container.getBoundingClientRect();
      this.dragOffset = {
        x: e.clientX - rect.left,
        y: e.clientY - rect.top
      };

      // Set container to absolute positioning if it isn't already
      if (this.container.style.position !== 'absolute') {
        const rect = this.container.getBoundingClientRect();
        this.container.style.position = 'absolute';
        this.container.style.left = rect.left + 'px';
        this.container.style.top = rect.top + 'px';
        this.container.style.width = rect.width + 'px';
        this.container.style.height = rect.height + 'px';
      }

      // Increase z-index when dragging starts
      this.container.style.zIndex = '1000';
    });

    const SNAP_THRESHOLD = 50; // Significantly increased snap distance threshold
    const SNAP_EDGE_THRESHOLD = 40; // Significantly increased edge snap threshold
    
    document.addEventListener('mousemove', (e) => {
      if (!this.isDragging) return;

      e.preventDefault();
      
      // Calculate position including scroll offset
      let x = e.clientX - this.dragOffset.x + window.scrollX;
      let y = e.clientY - this.dragOffset.y + window.scrollY;

      const rect = this.container.getBoundingClientRect();
      const maxX = window.innerWidth - rect.width;
      const maxY = window.innerHeight - rect.height;

      let snapped = false;

      // Snap to screen edges with improved precision and stronger effect
      if (x < SNAP_THRESHOLD) {
        const pull = x / SNAP_THRESHOLD;
        x = x * pull;
        if (x < SNAP_EDGE_THRESHOLD) {
          x = 0;
          snapped = true;
        }
      }
      if (y < SNAP_THRESHOLD) {
        const pull = y / SNAP_THRESHOLD;
        y = y * pull;
        if (y < SNAP_EDGE_THRESHOLD) {
          y = 0;
          snapped = true;
        }
      }
      if (x > maxX - SNAP_THRESHOLD) {
        const pull = (maxX - x) / SNAP_THRESHOLD;
        x = maxX - ((maxX - x) * pull);
        if (x > maxX - SNAP_EDGE_THRESHOLD) {
          x = maxX;
          snapped = true;
        }
      }
      if (y > maxY - SNAP_THRESHOLD) {
        const pull = (maxY - y) / SNAP_THRESHOLD;
        y = maxY - ((maxY - y) * pull);
        if (y > maxY - SNAP_EDGE_THRESHOLD) {
          y = maxY;
          snapped = true;
        }
      }

      // Enhanced panel snapping with magnetic pull effect
      document.querySelectorAll('.terminal').forEach(panel => {
        if (panel === this.container) return;
        
        const panelRect = panel.getBoundingClientRect();
        
        const PANEL_PADDING = 10; // Padding between snapped panels

        // Horizontal snapping with magnetic pull and padding
        const rightDiff = x - (panelRect.right + PANEL_PADDING);
        if (Math.abs(rightDiff) < SNAP_THRESHOLD) {
          const pull = 1 - (Math.abs(rightDiff) / SNAP_THRESHOLD);
          x = (panelRect.right + PANEL_PADDING) - (rightDiff * pull * pull);
          if (Math.abs(rightDiff) < SNAP_EDGE_THRESHOLD) {
            x = panelRect.right + PANEL_PADDING;
            snapped = true;
          }
        }

        const leftDiff = (x + rect.width) - (panelRect.left - PANEL_PADDING);
        if (Math.abs(leftDiff) < SNAP_THRESHOLD) {
          const pull = 1 - (Math.abs(leftDiff) / SNAP_THRESHOLD);
          x = (panelRect.left - PANEL_PADDING) - rect.width + (leftDiff * pull * pull);
          if (Math.abs(leftDiff) < SNAP_EDGE_THRESHOLD) {
            x = panelRect.left - PANEL_PADDING - rect.width;
            snapped = true;
          }
        }
        
        // Vertical snapping with magnetic pull and padding
        const bottomDiff = y - (panelRect.bottom + PANEL_PADDING);
        if (Math.abs(bottomDiff) < SNAP_THRESHOLD) {
          const pull = 1 - (Math.abs(bottomDiff) / SNAP_THRESHOLD);
          y = (panelRect.bottom + PANEL_PADDING) - (bottomDiff * pull * pull);
          if (Math.abs(bottomDiff) < SNAP_EDGE_THRESHOLD) {
            y = panelRect.bottom + PANEL_PADDING;
            snapped = true;
          }
        }

        const topDiff = (y + rect.height) - (panelRect.top - PANEL_PADDING);
        if (Math.abs(topDiff) < SNAP_THRESHOLD) {
          const pull = 1 - (Math.abs(topDiff) / SNAP_THRESHOLD);
          y = (panelRect.top - PANEL_PADDING) - rect.height + (topDiff * pull * pull);
          if (Math.abs(topDiff) < SNAP_EDGE_THRESHOLD) {
            y = panelRect.top - PANEL_PADDING - rect.height;
            snapped = true;
          }
        }
      });

      // Apply position with enhanced snap animation and magnetic feedback
      if (snapped) {
        this.container.style.transition = 'all 0.15s cubic-bezier(0.2, 0.8, 0.2, 1)';
        this.container.classList.add('snapping');
      } else {
        this.container.style.transition = '';
        this.container.style.transform = '';
        this.container.classList.remove('snapping');
      }

      // Ensure the window stays within viewport bounds
      x = Math.min(Math.max(0, x), maxX);
      y = Math.min(Math.max(0, y), maxY);

      this.container.style.left = x + 'px';
      this.container.style.top = y + 'px';
    });

    document.addEventListener('mouseup', () => {
      if (this.isDragging) {
        this.isDragging = false;
        // Store new position in originalDimensions
        this.saveCurrentDimensions();
      }
    });
  }

  saveInitialContent() {
    this.contentElements = {
      messages: this.container.querySelector('.chat-messages'),
      modalBody: this.container.querySelector('.modal-body'),
      messageForm: this.container.querySelector('#messageForm'),
      navigation: this.container.querySelector('.navigation-bar'),
      userList: this.container.querySelector('#userList'),
      categoryList: this.container.querySelector('#categoryList')
    };
  }

  minimize() {
    if (this.isMinimized) {
      // Restore from minimized state
      this.container.style.height = this.originalDimensions.height;
      Object.values(this.contentElements).forEach(element => {
        if (element) {
          element.style.display = '';
        }
      });
      this.isMinimized = false;
      this.container.classList.remove('minimized');
    } else {
      // Minimize
      this.saveCurrentDimensions();
      this.container.style.height = '40px';
      Object.values(this.contentElements).forEach(element => {
        if (element) {
          element.style.display = 'none';
        }
      });
      this.isMinimized = true;
      this.container.classList.add('minimized');
    }
  }

  maximize() {
    if (this.isMaximized) {
      // Restore from maximized state
      Object.keys(this.originalDimensions).forEach(prop => {
        this.container.style[prop] = this.originalDimensions[prop];
      });
      this.isMaximized = false;
      this.container.classList.remove('maximized');
    } else {
      // Maximize
      this.saveCurrentDimensions();
      this.container.style.position = 'fixed';
      this.container.style.width = '100%';
      this.container.style.height = '100%';
      this.container.style.top = '0';
      this.container.style.left = '0';
      this.container.style.right = '0';
      this.container.style.bottom = '0';
      this.container.style.zIndex = '9999';
      this.isMaximized = true;
      this.container.classList.add('maximized');
    }
  }

  close() {
    if (this.container.classList.contains('modal') || this.container.closest('.modal')) {
      // For modals, use Bootstrap's hide method
      const modalElement = this.container.classList.contains('modal') 
        ? this.container 
        : this.container.closest('.modal');
      const modal = bootstrap.Modal.getInstance(modalElement);
      if (modal) {
        modal.hide();
      }
    } else {
      // For regular panels, add a minimized class and hide
      this.container.style.display = 'none';
      const event = new CustomEvent('terminal:closed', {
        detail: { containerId: this.container.id }
      });
      document.dispatchEvent(event);
    }
  }

  saveCurrentDimensions() {
    const style = window.getComputedStyle(this.container);
    this.originalDimensions = {
      width: style.width,
      height: style.height,
      position: style.position,
      top: style.top,
      left: style.left,
      right: style.right,
      bottom: style.bottom,
      zIndex: style.zIndex
    };
    
    // Save state to localStorage
    this.savePanelState();
  }

  savePanelState() {
    if (!this.container.id) return; // Only save state for panels with IDs
    
    const state = {
      dimensions: this.originalDimensions,
      isMinimized: this.isMinimized,
      isMaximized: this.isMaximized
    };
    
    localStorage.setItem(`panel_state_${this.container.id}`, JSON.stringify(state));
  }

  loadPanelState() {
    if (!this.container.id) return;
    
    const savedState = localStorage.getItem(`panel_state_${this.container.id}`);
    if (!savedState) return;

    try {
      const state = JSON.parse(savedState);
      
      // Restore dimensions
      if (state.dimensions) {
        Object.keys(state.dimensions).forEach(prop => {
          this.container.style[prop] = state.dimensions[prop];
        });
        this.originalDimensions = state.dimensions;
      }

      // Restore minimized/maximized state
      if (state.isMinimized) {
        this.minimize();
      } else if (state.isMaximized) {
        this.maximize();
      }
    } catch (error) {
      console.error('Error loading panel state:', error);
    }
  }
}

// Initialize window controls for all terminal windows
document.addEventListener('DOMContentLoaded', () => {
  const initializeTerminal = (element) => {
    if (!element.dataset.terminalInitialized) {
      const terminal = new TerminalWindow(element);
      element.dataset.terminalInitialized = 'true';
      
      // Load saved state if available
      terminal.loadPanelState();
    }
  };

  // Initialize for main terminal windows
  document.querySelectorAll('.terminal').forEach(initializeTerminal);

  // Initialize for modals when they are shown
  document.querySelectorAll('.modal').forEach(modal => {
    modal.addEventListener('shown.bs.modal', () => {
      const modalContent = modal.querySelector('.modal-content');
      if (modalContent) {
        initializeTerminal(modalContent);
      }
    });
  });
});
