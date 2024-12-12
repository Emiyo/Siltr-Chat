// Window control functionality
class TerminalWindow {
  constructor(container) {
    this.container = container;
    this.originalDimensions = {
      width: container.style.width,
      height: container.style.height
    };
    this.isMinimized = false;
    this.isMaximized = false;
    this.setupControls();
  }

  setupControls() {
    const buttons = this.container.querySelector('.terminal-buttons');
    if (!buttons) return;

    // Close button (red)
    const closeBtn = buttons.querySelector('.terminal-button-red');
    if (closeBtn) {
      closeBtn.addEventListener('click', () => this.close());
    }

    // Minimize button (yellow)
    const minimizeBtn = buttons.querySelector('.terminal-button-yellow');
    if (minimizeBtn) {
      minimizeBtn.addEventListener('click', () => this.minimize());
    }

    // Maximize button (green)
    const maximizeBtn = buttons.querySelector('.terminal-button-green');
    if (maximizeBtn) {
      maximizeBtn.addEventListener('click', () => this.maximize());
    }
  }

  minimize() {
    if (this.isMinimized) {
      // Restore from minimized state
      this.container.style.height = this.originalDimensions.height || '100%';
      this.container.querySelector('.chat-messages, .modal-body')?.style.display = 'block';
      this.container.querySelector('#messageForm')?.style.display = 'block';
      this.isMinimized = false;
    } else {
      // Minimize
      this.saveCurrentDimensions();
      this.container.style.height = '40px';
      this.container.querySelector('.chat-messages, .modal-body')?.style.display = 'none';
      this.container.querySelector('#messageForm')?.style.display = 'none';
      this.isMinimized = true;
    }
  }

  maximize() {
    if (this.isMaximized) {
      // Restore from maximized state
      this.container.style.width = this.originalDimensions.width;
      this.container.style.height = this.originalDimensions.height;
      this.container.style.position = 'relative';
      this.container.style.top = 'auto';
      this.container.style.left = 'auto';
      this.container.style.right = 'auto';
      this.container.style.bottom = 'auto';
      this.container.style.zIndex = 'auto';
      this.isMaximized = false;
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
    }
  }

  close() {
    if (this.container.classList.contains('modal')) {
      // For modals, use Bootstrap's hide method
      const modal = bootstrap.Modal.getInstance(this.container);
      if (modal) {
        modal.hide();
      }
    } else {
      // For regular panels, minimize them
      this.minimize();
    }
  }

  saveCurrentDimensions() {
    this.originalDimensions = {
      width: this.container.style.width || this.container.offsetWidth + 'px',
      height: this.container.style.height || this.container.offsetHeight + 'px'
    };
  }
}

// Initialize window controls for all terminal windows
document.addEventListener('DOMContentLoaded', () => {
  // Initialize for main terminal windows
  document.querySelectorAll('.terminal').forEach(terminal => {
    new TerminalWindow(terminal);
  });

  // Initialize for modals when they are shown
  document.querySelectorAll('.modal').forEach(modal => {
    modal.addEventListener('shown.bs.modal', () => {
      new TerminalWindow(modal.querySelector('.modal-content'));
    });
  });
});
