"""
Enhanced UI Launcher - Professional Terminal Interface
Main entry point for the enhanced Wazuh DevSec Generator UI
"""

import sys
from pathlib import Path

from .interactive_app import WazuhInteractiveApp
from .terminal import EnhancedTerminalUI, UIConfig, UIStyle


def main():
    """Main launcher for enhanced UI"""
    try:
        # Create and run enhanced interactive app
        app = WazuhInteractiveApp()
        app.run()
        
    except KeyboardInterrupt:
        print("\n👋 Au revoir!")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Erreur: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
