"""
Enhanced Terminal UI - Clear and Interactive
Professional terminal interface with rich visual elements
"""

import os
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass
from enum import Enum

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.layout import Layout
from rich.text import Text
from rich.columns import Columns
from rich.align import Align
from rich.live import Live
from rich.tree import Tree
from rich.rule import Rule
from rich import box
from rich.markdown import Markdown
from rich.status import Status
import time


class UIStyle(str, Enum):
    """UI Style Themes"""
    PROFESSIONAL = "professional"
    MODERN = "modern"
    MINIMAL = "minimal"
    COLORFUL = "colorful"


@dataclass
class UIConfig:
    """UI Configuration"""
    style: UIStyle = UIStyle.PROFESSIONAL
    show_animations: bool = True
    show_progress_bars: bool = True
    show_status_icons: bool = True
    console_width: Optional[int] = None


class EnhancedTerminalUI:
    """Enhanced Terminal UI with rich visual elements"""
    
    def __init__(self, config: Optional[UIConfig] = None):
        self.config = config or UIConfig()
        self.console = Console(width=self.config.console_width)
        self._setup_styles()
        
    def _setup_styles(self):
        """Setup visual styles based on theme"""
        if self.config.style == UIStyle.PROFESSIONAL:
            self.colors = {
                "primary": "cyan",
                "secondary": "blue",
                "success": "green",
                "warning": "yellow",
                "error": "red",
                "info": "white",
                "accent": "magenta"
            }
            self.box_style = box.ROUNDED
        elif self.config.style == UIStyle.MODERN:
            self.colors = {
                "primary": "bright_blue",
                "secondary": "bright_cyan",
                "success": "bright_green",
                "warning": "bright_yellow",
                "error": "bright_red",
                "info": "bright_white",
                "accent": "bright_magenta"
            }
            self.box_style = box.SQUARE
        elif self.config.style == UIStyle.MINIMAL:
            self.colors = {
                "primary": "white",
                "secondary": "white",
                "success": "green",
                "warning": "yellow",
                "error": "red",
                "info": "white",
                "accent": "blue"
            }
            self.box_style = box.MINIMAL
        else:  # COLORFUL
            self.colors = {
                "primary": "rainbow",
                "secondary": "violet",
                "success": "spring_green",
                "warning": "gold1",
                "error": "red3",
                "info": "sky_blue1",
                "accent": "orchid1"
            }
            self.box_style = box.DOUBLE
    
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
        self.console.clear()
    
    def show_header(self, title: str, subtitle: str = ""):
        """Show beautiful header"""
        header_content = f"[{self.colors['primary']} bold]{title}[/{self.colors['primary']} bold]"
        if subtitle:
            header_content += f"\n[{self.colors['info']}]{subtitle}[/{self.colors['info']}]"
        
        panel = Panel(
            Align.center(header_content),
            box=self.box_style,
            border_style=self.colors['primary'],
            padding=(1, 2)
        )
        self.console.print(panel)
        self.console.print()
    
    def show_main_menu(self, options: List[Dict[str, Any]]) -> str:
        """Show interactive main menu"""
        self.clear_screen()
        self.show_header("🛡️  Wazuh DevSec Generator v2.0", "Professional Security Configuration Tool")
        
        # Create menu table
        table = Table(
            title=f"[{self.colors['secondary']}]Menu Principal[/{self.colors['secondary']}]",
            box=self.box_style,
            show_header=True,
            header_style=self.colors['accent'],
            border_style=self.colors['secondary']
        )
        table.add_column("Option", style=self.colors['primary'], width=8, justify="center")
        table.add_column("Description", style=self.colors['info'], width=40)
        table.add_column("Status", style=self.colors['success'], width=12, justify="center")
        
        for i, option in enumerate(options, 1):
            status_icon = "✅" if option.get('available', True) else "❌"
            status_text = f"[{self.colors['success']}]{status_icon}[/{self.colors['success']}]"
            
            table.add_row(
                f"[{self.colors['primary']}] {i}[/{self.colors['primary']}]",
                f"[{self.colors['info']}]{option['title']}[/{self.colors['info']}]",
                status_text
            )
        
        self.console.print(table)
        self.console.print()
        
        # Add footer
        footer = f"[{self.colors['info']}]Utilisez les chiffres pour naviguer • '0' pour quitter[/{self.colors['info']}]"
        self.console.print(Align.center(footer))
        
        # Get user choice
        choice = Prompt.ask(
            f"[{self.colors['accent']}]Choisissez une option[/{self.colors['accent']}]",
            choices=[str(i) for i in range(len(options) + 1)],
            default="0"
        )
        
        return choice
    
    def show_submenu(self, title: str, items: List[Dict[str, Any]], show_back: bool = True) -> str:
        """Show submenu with items"""
        self.clear_screen()
        self.show_header(title)
        
        table = Table(
            box=self.box_style,
            show_header=True,
            header_style=self.colors['accent'],
            border_style=self.colors['secondary']
        )
        table.add_column("Option", style=self.colors['primary'], width=6, justify="center")
        table.add_column("Nom", style=self.colors['info'], width=30)
        table.add_column("Description", style=self.colors['info'], width=40)
        
        for i, item in enumerate(items, 1):
            table.add_row(
                f"[{self.colors['primary']}] {i}[/{self.colors['primary']}]",
                f"[{self.colors['info']}]{item['name']}[/{self.colors['info']}]",
                f"[{self.colors['info']}] {item.get('description', '')}[/{self.colors['info']}]"
            )
        
        if show_back:
            table.add_row("", f"[{self.colors['warning']}]← Retour au menu principal[/{self.colors['warning']}]", "")
        
        self.console.print(table)
        
        choices = [str(i) for i in range(len(items) + (1 if show_back else 0))]
        choice = Prompt.ask(
            f"[{self.colors['accent']}]Choisissez une option[/{self.colors['accent']}]",
            choices=choices,
            default="0" if show_back else "1"
        )
        
        return choice
    
    def show_progress(self, title: str, steps: List[str]) -> None:
        """Show animated progress bar"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=self.console,
            transient=True
        ) as progress:
            task = progress.add_task(title, total=len(steps))
            
            for step in steps:
                progress.update(task, description=step)
                time.sleep(0.5)  # Simulate work
                progress.advance(task)
    
    def show_status(self, title: str, message: str, status_type: str = "info"):
        """Show status message"""
        status_colors = {
            "info": self.colors['info'],
            "success": self.colors['success'],
            "warning": self.colors['warning'],
            "error": self.colors['error']
        }
        
        color = status_colors.get(status_type, self.colors['info'])
        
        with Status(f"[{color}]{message}[/{color}]", console=self.console) as status:
            time.sleep(2)  # Simulate work
    
    def show_info_panel(self, title: str, content: str, expand: bool = True):
        """Show information panel"""
        panel = Panel(
            content,
            title=f"[{self.colors['accent']}]{title}[/{self.colors['accent']}]",
            border_style=self.colors['primary'],
            box=self.box_style,
            expand=expand
        )
        self.console.print(panel)
        self.console.print()
    
    def show_success(self, message: str):
        """Show success message"""
        self.console.print(f"[{self.colors['success']}]✅ {message}[/{self.colors['success']}]")
    
    def show_error(self, message: str):
        """Show error message"""
        self.console.print(f"[{self.colors['error']}]❌ {message}[/{self.colors['error']}]")
    
    def show_warning(self, message: str):
        """Show warning message"""
        self.console.print(f"[{self.colors['warning']}]⚠️  {message}[/{self.colors['warning']}]")
    
    def show_info(self, message: str):
        """Show info message"""
        self.console.print(f"[{self.colors['info']}]ℹ️  {message}[/{self.colors['info']}]")
    
    def show_table(self, title: str, data: List[Dict[str, Any]], columns: List[str]):
        """Show data table"""
        table = Table(
            title=f"[{self.colors['secondary']}]{title}[/{self.colors['secondary']}]",
            box=self.box_style,
            show_header=True,
            header_style=self.colors['accent'],
            border_style=self.colors['secondary']
        )
        
        # Add columns
        for column in columns:
            table.add_column(column, style=self.colors['info'])
        
        # Add rows
        for row in data:
            row_values = []
            for col in columns:
                value = row.get(col, "")
                # Convert int to string if needed
                if isinstance(value, int):
                    value = str(value)
                row_values.append(value)
            table.add_row(*row_values)
        
        self.console.print(table)
        self.console.print()
    
    def show_file_tree(self, title: str, path: Path, max_depth: int = 3):
        """Show directory tree"""
        self.console.print(f"[{self.colors['secondary']}]📁 {title}[/{self.colors['secondary']}]")
        
        tree = Tree(f"[{self.colors['primary']}]{path.name}[/{self.colors['primary']}]")
        
        def add_to_tree(parent, current_path, depth=0):
            if depth >= max_depth:
                return
            
            try:
                items = sorted(current_path.iterdir(), key=lambda x: (x.is_file(), x.name))
                for item in items:
                    if item.is_dir():
                        branch = parent.add(f"[{self.colors['accent']}📁 {item.name}[/{self.colors['accent']}]")
                        add_to_tree(branch, item, depth + 1)
                    else:
                        icon = "📄" if item.suffix in ['.txt', '.md', '.py'] else "📎"
                        parent.add(f"[{self.colors['info']}{icon} {item.name}[/{self.colors['info']}]")
            except PermissionError:
                parent.add(f"[{self.colors['warning']}]🔒 Permission refusée[/{self.colors['warning']}]")
        
        add_to_tree(tree, path)
        self.console.print(tree)
        self.console.print()
    
    def show_dashboard(self, metrics: Dict[str, Any]):
        """Show metrics dashboard"""
        # Create two-column layout
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3)
        )
        
        # Header
        header_content = f"[{self.colors['primary']} bold]📊 Tableau de Bord Wazuh[/{self.colors['primary']} bold]"
        layout["header"].update(Panel(header_content, box=self.box_style))
        
        # Body with metrics
        body_layout = Layout()
        body_layout.split_row(
            Layout(name="left"),
            Layout(name="right")
        )
        
        # Left column - System Status
        left_table = Table(
            title=f"[{self.colors['secondary']}]État Système[/{self.colors['secondary']}]",
            box=self.box_style,
            show_header=False
        )
        left_table.add_column("Métrique", style=self.colors['primary'])
        left_table.add_column("Valeur", style=self.colors['success'])
        
        for key, value in metrics.get('system', {}).items():
            left_table.add_row(key, str(value))
        
        layout["body"]["left"].update(Panel(left_table, box=self.box_style))
        
        # Right column - Components
        right_table = Table(
            title=f"[{self.colors['secondary']}]Composants[/{self.colors['secondary']}]",
            box=self.box_style,
            show_header=False
        )
        right_table.add_column("Composant", style=self.colors['primary'])
        right_table.add_column("État", style=self.colors['success'])
        
        for component, status in metrics.get('components', {}).items():
            status_icon = "✅" if status == "OK" else "❌"
            right_table.add_row(component, status_icon)
        
        layout["body"]["right"].update(Panel(right_table, box=self.box_style))
        
        layout["body"].update(body_layout)
        
        # Footer
        footer_content = f"[{self.colors['info']}]Dernière mise à jour: {time.strftime('%H:%M:%S')}[/{self.colors['info']}]"
        layout["footer"].update(Panel(footer_content, box=self.box_style))
        
        self.console.print(layout)
    
    def confirm_action(self, message: str, default: bool = False) -> bool:
        """Show confirmation dialog"""
        return Confirm.ask(
            f"[{self.colors['warning']}]⚠️  {message}[/{self.colors['warning']}]",
            default=default
        )
    
    def get_input(self, prompt: str, default: str = "", password: bool = False) -> str:
        """Get user input"""
        return Prompt.ask(
            f"[{self.colors['accent']}]❓ {prompt}[/{self.colors['accent']}]",
            default=default,
            password=password,
            show_default=True
        )
    
    def get_choice(self, prompt: str, choices: List[str], default: str = None) -> str:
        """Get user choice from list"""
        return Prompt.ask(
            f"[{self.colors['accent']}]❓ {prompt}[/{self.colors['accent']}]",
            choices=choices,
            default=default
        )
    
    def show_loading(self, message: str, duration: float = 2.0):
        """Show loading animation"""
        with Status(f"[{self.colors['primary']}]⏳ {message}[/{self.colors['primary']}]", console=self.console):
            time.sleep(duration)
    
    def show_alert(self, title: str, message: str, alert_type: str = "info"):
        """Show alert box"""
        alert_colors = {
            "info": self.colors['info'],
            "success": self.colors['success'],
            "warning": self.colors['warning'],
            "error": self.colors['error']
        }
        
        alert_icons = {
            "info": "ℹ️",
            "success": "✅",
            "warning": "⚠️",
            "error": "❌"
        }
        
        color = alert_colors.get(alert_type, self.colors['info'])
        icon = alert_icons.get(alert_type, "ℹ️")
        
        content = f"[{color}]{icon} {message}[/{color}]"
        panel = Panel(
            content,
            title=f"[{color}]{title}[/{color}]",
            border_style=color,
            box=self.box_style
        )
        
        self.console.print(panel)
        self.console.print()
    
    def pause(self, message: str = "Appuyez sur Entrée pour continuer..."):
        """Pause execution"""
        self.console.print(f"[{self.colors['info']}]⏸️  {message}[/{self.colors['info']}]")
        input()
    
    def show_separator(self, title: str = ""):
        """Show visual separator"""
        if title:
            self.console.print(Rule(f"[{self.colors['accent']}] {title} ", align="center"))
        else:
            self.console.print(Rule(style=self.colors['secondary']))
    
    def show_columns(self, items: List[str], equal_width: bool = True):
        """Show items in columns"""
        columns_obj = Columns(items, equal_width=equal_width, expand=True)
        self.console.print(columns_obj)
        self.console.print()
