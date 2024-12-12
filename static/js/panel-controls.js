// Panel control functionality
class PanelController {
  constructor() {
    this.panels = {};
    this.initializePanels();
  }

  initializePanels() {
    // Get all terminal panels
    document.querySelectorAll('.terminal').forEach((panel) => {
      const header = panel.querySelector('.terminal-header');
      if (!header) return;

      // Store original dimensions
      const panelId = panel.parentElement.classList[0];
      this.panels[panelId] = {
        element: panel,
        minimized: false,
        maximized: false,
        originalDimensions: {
          width: panel.style.width || '100%',
          height: panel.style.height || '100%',
          position: panel.style.position || 'relative',
          top: panel.style.top || 'auto',
          left: panel.style.left || 'auto',
          zIndex: panel.style.zIndex || 'auto'
        }
      };

      // Add event listeners to buttons
      const buttons = header.querySelectorAll('.terminal-button');
      buttons.forEach((button) => {
        if (button.classList.contains('terminal-button-red')) {
          button.addEventListener('click', () => this.closePanel(panelId));
        } else if (button.classList.contains('terminal-button-yellow')) {
          button.addEventListener('click', () => this.minimizePanel(panelId));
        } else if (button.classList.contains('terminal-button-green')) {
          button.addEventListener('click', () => this.maximizePanel(panelId));
        }
      });
    });
  }

  minimizePanel(panelId) {
    const panel = this.panels[panelId];
    if (!panel) return;

    if (panel.minimized) {
      // Restore
      panel.element.style.height = panel.originalDimensions.height;
      panel.element.querySelector('.chat-messages, #userList, #categoryList').style.display = 'block';
      panel.element.querySelector('form')?.style.display = 'block';
      panel.minimized = false;
    } else {
      // Minimize
      panel.element.style.height = '40px';
      panel.element.querySelector('.chat-messages, #userList, #categoryList').style.display = 'none';
      panel.element.querySelector('form')?.style.display = 'none';
      panel.minimized = true;
      if (panel.maximized) {
        this.maximizePanel(panelId); // Reset maximized state
      }
    }
  }

  maximizePanel(panelId) {
    const panel = this.panels[panelId];
    if (!panel) return;

    if (panel.maximized) {
      // Restore
      Object.assign(panel.element.style, panel.originalDimensions);
      panel.element.classList.remove('maximized-panel');
      panel.maximized = false;
    } else {
      // Maximize
      panel.element.style.position = 'fixed';
      panel.element.style.top = '0';
      panel.element.style.left = '0';
      panel.element.style.width = '100vw';
      panel.element.style.height = '100vh';
      panel.element.style.zIndex = '9999';
      panel.element.classList.add('maximized-panel');
      panel.maximized = true;
      if (panel.minimized) {
        this.minimizePanel(panelId); // Reset minimized state
      }
    }
  }

  closePanel(panelId) {
    const panel = this.panels[panelId];
    if (!panel) return;

    // Add closing animation
    panel.element.style.transition = 'all 0.3s ease';
    panel.element.style.opacity = '0';
    panel.element.style.transform = 'scale(0.9)';

    // After animation, hide the panel
    setTimeout(() => {
      panel.element.style.display = 'none';
    }, 300);
  }
}

// Initialize panel controls when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  window.panelController = new PanelController();
});
