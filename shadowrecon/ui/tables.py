from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box


console = Console()


def status_table(module_results):
    table = Table(
        box=box.SIMPLE_HEAVY,
        expand=True,
    )

    table.add_column(
        "MODULE",
        style="bold cyan",
    )

    table.add_column(
        "STATUS",
        style="white",
    )

    table.add_column(
        "RESULT",
        style="white",
    )

    for item in module_results:
        module = item.get(
            "module",
            "UNKNOWN",
        )

        status = item.get(
            "status",
            "UNKNOWN",
        )

        result = item.get(
            "result",
            "N/A",
        )

        if status == "COMPLETE":
            status_display = (
                "[bold green]COMPLETE[/bold green]"
            )

        elif status in (
            "ERROR",
            "FAILED",
        ):
            status_display = (
                "[bold red]"
                f"{status}"
                "[/bold red]"
            )

        elif status in (
            "RUNNING",
            "SCANNING",
        ):
            status_display = (
                "[bold yellow]"
                f"{status}"
                "[/bold yellow]"
            )

        else:
            status_display = status

        table.add_row(
            module,
            status_display,
            str(result),
        )

    return Panel(
        table,
        title=(
            "[bold cyan]"
            "RECONNAISSANCE ENGINE"
            "[/bold cyan]"
        ),
        border_style="cyan",
        box=box.ROUNDED,
    )


def intelligence_table(
    ip_addresses=None,
    open_ports=None,
    technologies=None,
    endpoints=0,
    contacts=0,
    exposure=0,
):
    table = Table(
        box=None,
        expand=True,
    )

    table.add_column(
        "INTELLIGENCE",
        style="bold cyan",
    )

    table.add_column(
        "VALUE",
        style="white",
    )

    ip_addresses = ip_addresses or []
    open_ports = open_ports or []
    technologies = technologies or []

    if ip_addresses:
        ip_display = ", ".join(
            str(item)
            for item in ip_addresses
        )
    else:
        ip_display = "N/A"

    if open_ports:
        port_display = ", ".join(
            str(item)
            for item in open_ports
        )
    else:
        port_display = "None"

    if technologies:
        technology_names = []

        for item in technologies:
            if isinstance(item, dict):
                name = item.get(
                    "name",
                    "Unknown",
                )
            else:
                name = str(item)

            technology_names.append(name)

        technology_display = ", ".join(
            technology_names
        )
    else:
        technology_display = "N/A"

    table.add_row(
        "IP Addresses",
        ip_display,
    )

    table.add_row(
        "Open Ports",
        port_display,
    )

    table.add_row(
        "Technologies",
        technology_display,
    )

    table.add_row(
        "Endpoints",
        str(endpoints),
    )

    table.add_row(
        "Public Contacts",
        str(contacts),
    )

    table.add_row(
        "Exposure Indicators",
        str(exposure),
    )

    return Panel(
        table,
        title=(
            "[bold cyan]"
            "FINAL INTELLIGENCE"
            "[/bold cyan]"
        ),
        border_style="cyan",
        box=box.ROUNDED,
    )
