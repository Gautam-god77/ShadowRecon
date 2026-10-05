from rich.console import Console
from rich.panel import Panel
from rich.align import Align
from rich.text import Text
from rich import box

console = Console()


def show_banner():
    logo = Text()

    logo.append(
        """
 ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗
 ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔══██╗██║    ██║
 ███████╗███████║███████║██║  ██║██║  ██║██║ █╗ ██║
 ╚════██║██╔══██║██╔══██║██║  ██║██║  ██║██║███╗██║
 ███████║██║  ██║██║  ██║██████╔╝██████╔╝╚███╔███╔╝
 ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═════╝  ╚══╝╚══╝
""",
        style="bold cyan",
    )

    logo.append(
        "\n              ADVANCED RECONNAISSANCE FRAMEWORK\n"
        "                         VERSION 1.0.0",
        style="bold white",
    )

    console.print(
        Panel(
            Align.center(logo),
            border_style="cyan",
            box=box.DOUBLE,
            padding=(1, 2),
        )
    )
