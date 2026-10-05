from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box


console = Console()


def target_panel(target, target_type, profile):

    table = Table(
        box=None,
        show_header=False,
        expand=True,
    )

    table.add_row(
        "[bold cyan]>[/bold cyan] TARGET",
        target
    )

    table.add_row(
        "[bold cyan]>[/bold cyan] TYPE",
        target_type
    )

    table.add_row(
        "[bold cyan]>[/bold cyan] PROFILE",
        profile
    )

    table.add_row(
        "[bold cyan]>[/bold cyan] OUTPUT",
        "TERMINAL"
    )

    console.print(
        Panel(
            table,
            title="[bold cyan]TARGET CONFIGURATION[/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )


def engine_panel():

    table = Table(
        box=None,
        show_header=False,
        expand=True,
    )

    modules = [
        ("DNS", "COMPLETE"),
        ("SUBDOMAINS", "COMPLETE"),
        ("HTTP", "COMPLETE"),
        ("PORTS", "WAITING"),
        ("TECHNOLOGY", "WAITING"),
        ("ENDPOINTS", "WAITING"),
        ("HEADERS", "WAITING"),
    ]

    for module, status in modules:

        if status == "COMPLETE":
            style = "green"
        else:
            style = "yellow"

        table.add_row(
            f"[cyan]{module:<15}[/cyan]",
            f"[{style}]{status}[/{style}]"
        )

    console.print(
        Panel(
            table,
            title="[bold cyan]RECONNAISSANCE ENGINE[/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )


def intelligence_panel():

    table = Table(
        box=None,
        show_header=False,
        expand=True,
    )

    table.add_row(
        "PUBLIC IP",
        "N/A"
    )

    table.add_row(
        "LOCATION",
        "N/A"
    )

    table.add_row(
        "OPEN PORTS",
        "N/A"
    )

    table.add_row(
        "SERVICES",
        "N/A"
    )

    table.add_row(
        "TECHNOLOGY",
        "N/A"
    )

    console.print(
        Panel(
            table,
            title="[bold cyan]LIVE INTELLIGENCE[/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )


def dns_panel(results):

    table = Table(
        box=None,
        expand=True,
    )

    table.add_column(
        "TYPE",
        style="bold cyan",
        width=10,
    )

    table.add_column(
        "RECORD",
        style="white",
    )

    found = False

    for record_type, records in results.items():

        if not records:
            continue

        found = True

        for record in records:

            table.add_row(
                record_type,
                record,
            )

    if not found:

        table.add_row(
            "INFO",
            "No DNS records discovered",
        )

    console.print(
        Panel(
            table,
            title="[bold cyan]DNS INTELLIGENCE[/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )


def subdomain_panel(results):

    table = Table(
        box=None,
        expand=True,
    )

    table.add_column(
        "SUBDOMAIN",
        style="bold cyan",
    )

    table.add_column(
        "IP ADDRESS",
        style="white",
    )

    table.add_column(
        "STATUS",
        style="bold green",
        width=12,
    )

    if not results:

        table.add_row(
            "N/A",
            "N/A",
            "NOT FOUND",
        )

    else:

        for result in results:

            addresses = ", ".join(
                result["addresses"]
            )

            table.add_row(
                result["hostname"],
                addresses,
                result["status"],
            )

    console.print(
        Panel(
            table,
            title="[bold cyan]SUBDOMAIN INTELLIGENCE[/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )


def http_panel(result):

    table = Table(
        box=None,
        expand=True,
        show_header=True,
    )

    table.add_column(
        "PROPERTY",
        style="bold cyan",
        width=20,
    )

    table.add_column(
        "VALUE",
        style="white",
    )

    if not result.get("reachable"):

        table.add_row(
            "STATUS",
            "[red]UNREACHABLE[/red]"
        )

        table.add_row(
            "ERROR",
            result.get(
                "error",
                "Unknown error"
            )
        )

    else:

        status_code = result.get(
            "status_code"
        )

        if status_code and status_code < 400:
            status_style = "green"
        elif status_code and status_code < 500:
            status_style = "yellow"
        else:
            status_style = "red"

        table.add_row(
            "STATUS CODE",
            f"[{status_style}]"
            f"{status_code}"
            f"[/{status_style}]"
        )

        table.add_row(
            "SCHEME",
            result.get(
                "scheme",
                "N/A"
            )
        )

        table.add_row(
            "FINAL URL",
            result.get(
                "final_url",
                "N/A"
            )
        )

        table.add_row(
            "PAGE TITLE",
            result.get(
                "title",
                "N/A"
            )
        )

        table.add_row(
            "SERVER",
            result.get(
                "server",
                "N/A"
            )
        )

        table.add_row(
            "CONTENT TYPE",
            result.get(
                "content_type",
                "N/A"
            )
        )

        table.add_row(
            "CONTENT LENGTH",
            result.get(
                "content_length",
                "N/A"
            )
        )

        table.add_row(
            "RESPONSE TIME",
            f"{result.get('response_time', 'N/A')} ms"
        )

        redirects = result.get(
            "redirects",
            []
        )

        table.add_row(
            "REDIRECTS",
            str(len(redirects))
        )

    console.print(
        Panel(
            table,
            title="[bold cyan]HTTP INTELLIGENCE[/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )

def ip_panel(result):

    table = Table(
        box=None,
        expand=True,
    )

    table.add_column(
        "PROPERTY",
        style="bold cyan",
        width=20,
    )

    table.add_column(
        "VALUE",
        style="white",
    )

    hostname = result.get(
        "hostname"
    )

    if hostname:

        table.add_row(
            "HOSTNAME",
            hostname
        )

    ipv4 = result.get(
        "ipv4",
        []
    )

    ipv6 = result.get(
        "ipv6",
        []
    )

    all_ips = result.get(
        "all_ips",
        []
    )

    classifications = result.get(
        "classifications",
        {}
    )

    table.add_row(
        "IPv4",
        ", ".join(ipv4)
        if ipv4
        else "N/A"
    )

    table.add_row(
        "IPv6",
        ", ".join(ipv6)
        if ipv6
        else "N/A"
    )

    if all_ips:

        for address in all_ips:

            classification = classifications.get(
                address,
                "UNKNOWN"
            )

            if classification == "PUBLIC":
                style = "green"

            elif classification == "PRIVATE":
                style = "yellow"

            else:
                style = "cyan"

            table.add_row(
                f"CLASSIFICATION\n{address}",
                f"[{style}]"
                f"{classification}"
                f"[/{style}]"
            )

    else:

        table.add_row(
            "STATUS",
            "[red]NO IP FOUND[/red]"
        )

    if result.get("error"):

        table.add_row(
            "ERROR",
            result["error"]
        )

    console.print(
        Panel(
            table,
            title="[bold cyan]IP INTELLIGENCE[/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )

def location_panel(results):

    table = Table(
        box=None,
        expand=True,
    )

    table.add_column(
        "IP",
        style="bold cyan",
    )

    table.add_column(
        "COUNTRY",
        style="white",
    )

    table.add_column(
        "ASN",
        style="white",
    )

    table.add_column(
        "ORGANIZATION",
        style="white",
    )

    if not results:

        table.add_row(
            "N/A",
            "N/A",
            "N/A",
            "N/A",
        )

    else:

        for result in results:

            ip = result.get(
                "ip",
                "N/A"
            )

            country = result.get(
                "country",
                "N/A"
            )

            country_code = result.get(
                "country_code",
                "N/A"
            )

            asn = result.get(
                "asn",
                "N/A"
            )

            organization = result.get(
                "organization",
                "N/A"
            )

            if result.get("status") == "SUCCESS":

                country_display = (
                    f"{country} "
                    f"({country_code})"
                )

            elif result.get("status") == "NOT PUBLIC":

                country_display = (
                    "[yellow]PRIVATE / LOCAL[/yellow]"
                )

            else:

                country_display = (
                    "[dim]N/A[/dim]"
                )

            table.add_row(
                ip,
                country_display,
                asn,
                organization,
            )

    console.print(
        Panel(
            table,
            title="[bold cyan]LOCATION & ASN INTELLIGENCE[/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )
