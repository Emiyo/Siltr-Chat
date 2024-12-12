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
      const panelId = panel.id || `panel-${Math.random().toString(36).substr(2, 9)}`;
      panel.id = panelId;
      
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
          button.addEventListener('click', (e) => {
            e.stopPropagation();
            this.closePanel(panelId);
          });
        } else if (button.classList.contains('terminal-button-yellow')) {
          button.addEventListener('click', (e) => {
            e.stopPropagation();
            this.minimizePanel(panelId);
          });
        } else if (button.classList.contains('terminal-button-green')) {
          button.addEventListener('click', (e) => {
            e.stopPropagation();
            this.maximizePanel(panelId);
          });
        }
      });

      // Store initial sizes
      const rect = panel.getBoundingClientRect();
      this.panels[panelId].originalDimensions = {
        ...this.panels[panelId].originalDimensions,
        width: `${rect.width}px`,
        height: `${rect.height}px`
      };
    });
  }

  minimizePanel(panelId) {
    const panel = this.panels[panelId];
    if (!panel) return;

    const content = panel.element.querySelector('.chat-messages, .p-2, form');
    if (!content) return;

    if (panel.minimized) {
      // Restore
      content.style.display = 'block';
      panel.element.style.height = panel.originalDimensions.height;
      panel.minimized = false;
    } else {
      // Minimize
      content.style.display = 'none';
      panel.element.style.height = '32px';
      panel.minimized = true;

      // If panel was maximized, restore it first
      if (panel.maximized) {
        this.maximizePanel(panelId);
      }
    }
  }

  maximizePanel(panelId) {
    const panel = this.panels[panelId];
    if (!panel) return;

    if (panel.maximized) {
      // Restore
      Object.entries(panel.originalDimensions).forEach(([prop, value]) => {
        panel.element.style[prop] = value;
      });
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

      // If panel was minimized, restore it first
      if (panel.minimized) {
        this.minimizePanel(panelId);
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
