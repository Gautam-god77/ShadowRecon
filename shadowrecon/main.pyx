from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich.table import Table
from rich import box


console = Console()


def show_banner():
    banner = Text()
    banner.append("S H A D O W R E C O N\n", style="bold cyan")
    banner.append(
        "ADVANCED RECONNAISSANCE FRAMEWORK",
        style="bold white"
    )

    console.print(
        Panel(
            Align.center(banner),
            border_style="cyan",
            box=box.DOUBLE,
            padding=(1, 4),
        )
    )


def show_target_menu():
    console.print()

    target_panel = Panel(
        "[bold white]Target Domain / IP[/bold white]\n\n"
        "[cyan]>[/cyan] ",
        title="[bold cyan]TARGET CONFIGURATION[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    )

    console.print(target_panel)

    target = console.input("[bold cyan]Target → [/bold cyan]")

    return target


def show_scan_profiles():
    console.print()

    table = Table(
        title="SCAN PROFILE",
        box=box.ROUNDED,
        border_style="cyan",
    )

    table.add_column("ID", style="cyan", justify="center")
    table.add_column("PROFILE", style="white")
    table.add_column("DESCRIPTION", style="dim")

    table.add_row(
        "1",
        "QUICK",
        "Basic DNS and HTTP reconnaissance"
    )

    table.add_row(
        "2",
        "STANDARD",
        "DNS, subdomains, HTTP and technology"
    )

    table.add_row(
        "3",
        "FULL",
        "Complete authorized reconnaissance"
    )

    console.print(table)

    profile = console.input(
        "\n[bold cyan]Select Profile → [/bold cyan]"
    )

    return profile


def main():
    console.clear()

    show_banner()

    console.print(
        "\n[bold green]● SYSTEM READY[/bold green]"
    )

    target = show_target_menu()
    profile = show_scan_profiles()

    console.print()

    console.print(
        Panel(
            f"[bold white]TARGET[/bold white]      : {target}\n"
            f"[bold white]PROFILE[/bold white]     : {profile}\n"
            f"[bold white]OUTPUT[/bold white]      : TERMINAL\n"
            f"[bold white]GEOLOCATION[/bold white] : PUBLIC IP ONLY",
            title="[bold cyan]SCAN CONFIGURATION[/bold cyan]",
            border_style="cyan",
        )
    )

    console.print(
        "\n[bold cyan]Press ENTER to initialize reconnaissance...[/bold cyan]"
    )

    input()

    console.print(
        "\n[bold green]✓ Reconnaissance engine initialized[/bold green]"
    )


if __name__ == "__main__":
    main()
