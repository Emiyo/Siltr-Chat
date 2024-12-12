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

    const SNAP_THRESHOLD = 20; // px distance to trigger snapping
    const SNAP_EDGE_THRESHOLD = 10; // px distance to trigger edge snapping

    document.addEventListener('mousemove', (e) => {
      if (!this.isDragging) return;

      e.preventDefault();
      
      let x = e.clientX - this.dragOffset.x;
      let y = e.clientY - this.dragOffset.y;

      const rect = this.container.getBoundingClientRect();
      const maxX = window.innerWidth - rect.width;
      const maxY = window.innerHeight - rect.height;

      // Snap to screen edges
      if (x < SNAP_EDGE_THRESHOLD) x = 0;
      if (y < SNAP_EDGE_THRESHOLD) y = 0;
      if (x > maxX - SNAP_EDGE_THRESHOLD) x = maxX;
      if (y > maxY - SNAP_EDGE_THRESHOLD) y = maxY;

      // Snap to other panels
      document.querySelectorAll('.terminal').forEach(panel => {
        if (panel === this.container) return;
        
        const panelRect = panel.getBoundingClientRect();
        
        // Snap horizontally
        if (Math.abs(x - panelRect.right) < SNAP_THRESHOLD) x = panelRect.right;
        if (Math.abs(x + rect.width - panelRect.left) < SNAP_THRESHOLD) x = panelRect.left - rect.width;
        
        // Snap vertically
        if (Math.abs(y - panelRect.bottom) < SNAP_THRESHOLD) y = panelRect.bottom;
        if (Math.abs(y + rect.height - panelRect.top) < SNAP_THRESHOLD) y = panelRect.top - rect.height;
      });

      // Apply position with smooth transition
      this.container.style.transition = 'all 0.1s ease-out';
      this.container.style.left = Math.min(Math.max(0, x), maxX) + 'px';
      this.container.style.top = Math.min(Math.max(0, y), maxY) + 'px';
      
      // Remove transition after snap
      setTimeout(() => {
        this.container.style.transition = '';
      }, 100);
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
  }
}

// Initialize window controls for all terminal windows
document.addEventListener('DOMContentLoaded', () => {
  const initializeTerminal = (element) => {
    if (!element.dataset.terminalInitialized) {
      new TerminalWindow(element);
      element.dataset.terminalInitialized = 'true';
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
