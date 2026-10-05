import os
import sys
import time

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from shadowrecon.core.scanner import Scanner

from shadowrecon.modules.dns import scan_dns
from shadowrecon.modules.subdomains import discover_subdomains
from shadowrecon.modules.http import scan_http
from shadowrecon.modules.ip_info import scan_ip
from shadowrecon.modules.location_info import scan_location
from shadowrecon.modules.mac_info import scan_mac
from shadowrecon.modules.ports import scan_ports
from shadowrecon.modules.technology import scan_technology
from shadowrecon.modules.headers import scan_headers
from shadowrecon.modules.endpoints import scan_endpoints
from shadowrecon.modules.contact_info import scan_contact_info
from shadowrecon.modules.exposure import scan_exposure

from shadowrecon.ui.banner import show_banner


console = Console()


def clear_screen():
    os.system("clear")


def print_section(title):
    console.print()

    console.print(
        Panel(
            f"[bold cyan]{title}[/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )


def ask_target():
    console.print(
        "[bold white]Enter target domain, IP or URL:[/bold white]"
    )

    target = input("> ").strip()

    if not target:
        console.print(
            "[bold red]Target cannot be empty.[/bold red]"
        )
        sys.exit(1)

    return target


def authorization_prompt(target):
    console.print()

    console.print(
        Panel(
            "[bold yellow]"
            "AUTHORIZED USE ONLY\n\n"
            "Confirm that you are authorized to "
            "perform reconnaissance against:\n\n"
            f"[bold white]{target}[/bold white]\n\n"
            "The scan will perform network and web "
            "reconnaissance."
            "[/bold yellow]",
            title="[bold red]SCOPE CONFIRMATION[/bold red]",
            border_style="yellow",
            box=box.DOUBLE,
        )
    )

    answer = input(
        "Type AUTHORIZED to continue: "
    ).strip()

    return answer == "AUTHORIZED"


def module_status(name, status):
    if status == "COMPLETE":
        return (
            f"[bold green]✓ {name:<18} "
            f"COMPLETE[/bold green]"
        )

    if status in (
        "ERROR",
        "FAILED",
    ):
        return (
            f"[bold red]✗ {name:<18} "
            f"{status}[/bold red]"
        )

    return (
        f"[yellow]• {name:<18} "
        f"{status}[/yellow]"
    )


def safe_run(name, function):
    """
    Run a module without allowing one failed
    module to stop the entire reconnaissance.
    """

    console.print(
        module_status(
            name,
            "RUNNING",
        )
    )

    start = time.perf_counter()

    try:
        result = function()

        elapsed = round(
            time.perf_counter() - start,
            2,
        )

        if isinstance(result, dict):
            status = result.get(
                "status",
                "COMPLETE",
            )

            if status in (
                "ERROR",
                "NMAP ERROR",
                "TIMEOUT",
                "INVALID TARGET",
            ):
                console.print(
                    module_status(
                        name,
                        "ERROR",
                    )
                )
            else:
                console.print(
                    module_status(
                        name,
                        "COMPLETE",
                    )
                )

            console.print(
                f"  [dim]Completed in "
                f"{elapsed}s[/dim]"
            )

            return result

        console.print(
            module_status(
                name,
                "COMPLETE",
            )
        )

        console.print(
            f"  [dim]Completed in "
            f"{elapsed}s[/dim]"
        )

        return result

    except Exception as error:
        console.print(
            module_status(
                name,
                "ERROR",
            )
        )

        console.print(
            f"  [red]Error: {error}[/red]"
        )

        return {
            "status": "ERROR",
            "error": str(error),
        }


def display_target(target, authorized):
    table = Table(
        box=None,
        expand=True,
    )

    table.add_column(
        "FIELD",
        style="bold cyan",
    )

    table.add_column(
        "VALUE",
        style="white",
    )

    table.add_row(
        "Original",
        target.original,
    )

    table.add_row(
        "Type",
        target.target_type,
    )

    table.add_row(
        "Host",
        target.host,
    )

    if target.url:
        table.add_row(
            "URL",
            target.url,
        )

    authorization = (
        "[bold green]CONFIRMED[/bold green]"
        if authorized
        else "[bold red]NOT CONFIRMED[/bold red]"
    )

    table.add_row(
        "Authorization",
        authorization,
    )

    console.print(
        Panel(
            table,
            title="[bold cyan]TARGET INFORMATION[/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )


def display_dns(results):
    table = Table(
        box=None,
        expand=True,
    )

    table.add_column(
        "TYPE",
        style="bold cyan",
    )

    table.add_column(
        "RECORDS",
        style="white",
    )

    for record_type, records in results.items():
        if records:
            value = "\n".join(records)
        else:
            value = "N/A"

        table.add_row(
            record_type,
            value,
        )

    console.print(
        Panel(
            table,
            title="[bold cyan]DNS INTELLIGENCE[/bold cyan]",
            border_style="cyan",
        )
    )


def display_subdomains(results):
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

    if not results:
        table.add_row(
            "None discovered",
            "N/A",
        )

    for item in results:
        table.add_row(
            item.get(
                "hostname",
                "N/A",
            ),
            ", ".join(
                item.get(
                    "addresses",
                    [],
                )
            ),
        )

    console.print(
        Panel(
            table,
            title="[bold cyan]SUBDOMAIN DISCOVERY[/bold cyan]",
            border_style="cyan",
        )
    )


def display_http(result):
    table = Table(
        box=None,
        expand=True,
    )

    table.add_column(
        "PROPERTY",
        style="bold cyan",
    )

    table.add_column(
        "VALUE",
        style="white",
    )

    fields = (
        ("Status Code", "status_code"),
        ("Title", "title"),
        ("Final URL", "final_url"),
        ("Server", "server"),
        ("Content Type", "content_type"),
        ("Response Time", "response_time"),
    )

    for label, key in fields:
        table.add_row(
            label,
            str(result.get(key, "N/A")),
        )

    console.print(
        Panel(
            table,
            title="[bold cyan]HTTP INFORMATION[/bold cyan]",
            border_style="cyan",
        )
    )


def display_ip(result):
    table = Table(
        box=None,
        expand=True,
    )

    table.add_column(
        "IP",
        style="bold cyan",
    )

    table.add_column(
        "TYPE",
        style="white",
    )

    addresses = result.get(
        "all_ips",
        [],
    )

    if not addresses:
        table.add_row(
            "N/A",
            "N/A",
        )

    for address in addresses:
        table.add_row(
            address,
            result.get(
                "classifications",
                {},
            ).get(
                address,
                "N/A",
            ),
        )

    console.print(
        Panel(
            table,
            title="[bold cyan]IP INTELLIGENCE[/bold cyan]",
            border_style="cyan",
        )
    )


def display_location(results):
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

    for item in results:
        country = item.get(
            "country",
            "N/A",
        )

        country_code = item.get(
            "country_code",
            "N/A",
        )

        if item.get("status") == "SUCCESS":
            country = (
                f"{country} "
                f"({country_code})"
            )

        table.add_row(
            item.get("ip", "N/A"),
            country,
            item.get("asn", "N/A"),
            item.get(
                "organization",
                "N/A",
            ),
        )

    console.print(
        Panel(
            table,
            title="[bold cyan]LOCATION / ASN INTELLIGENCE[/bold cyan]",
            border_style="cyan",
        )
    )


def display_ports(result):
    table = Table(
        box=None,
        expand=True,
    )

    table.add_column(
        "PORT",
        style="bold cyan",
    )

    table.add_column(
        "PROTO",
        style="white",
    )

    table.add_column(
        "STATE",
        style="white",
    )

    table.add_column(
        "SERVICE",
        style="white",
    )

    table.add_column(
        "VERSION",
        style="white",
    )

    ports = result.get(
        "ports",
        [],
    )

    if not ports:
        table.add_row(
            "N/A",
            "N/A",
            "N/A",
            "N/A",
            "N/A",
        )

    for item in ports:
        if item.get("state") != "open":
            continue

        version = item.get(
            "version",
            "N/A",
        )

        table.add_row(
            str(item.get("port", "N/A")),
            item.get(
                "protocol",
                "N/A",
            ),
            item.get(
                "state",
                "N/A",
            ),
            item.get(
                "service",
                "N/A",
            ),
            version,
        )

    console.print(
        Panel(
            table,
            title="[bold cyan]PORT / SERVICE DISCOVERY[/bold cyan]",
            border_style="cyan",
        )
    )


def display_technology(result):
    table = Table(
        box=None,
        expand=True,
    )

    table.add_column(
        "TECHNOLOGY",
        style="bold cyan",
    )

    table.add_column(
        "CATEGORY",
        style="white",
    )

    table.add_column(
        "EVIDENCE",
        style="dim",
    )

    technologies = result.get(
        "technologies",
        [],
    )

    if not technologies:
        table.add_row(
            "None detected",
            "N/A",
            "N/A",
        )

    for item in technologies:
        table.add_row(
            item.get(
                "name",
                "N/A",
            ),
            item.get(
                "category",
                "N/A",
            ),
            item.get(
                "evidence",
                "N/A",
            ),
        )

    console.print(
        Panel(
            table,
            title="[bold cyan]TECHNOLOGY DETECTION[/bold cyan]",
            border_style="cyan",
        )
    )


def display_headers(result):
    table = Table(
        box=None,
        expand=True,
    )

    table.add_column(
        "HEADER",
        style="bold cyan",
    )

    table.add_column(
        "STATUS",
        style="white",
    )

    headers = result.get(
        "headers",
        [],
    )

    for item in headers:
        status = item.get(
            "status",
            "N/A",
        )

        if status == "PRESENT":
            status_display = (
                "[green]PRESENT[/green]"
            )
        else:
            status_display = (
                "[yellow]MISSING[/yellow]"
            )

        table.add_row(
            item.get(
                "name",
                "N/A",
            ),
            status_display,
        )

    console.print(
        Panel(
            table,
            title="[bold cyan]SECURITY HEADERS[/bold cyan]",
            border_style="cyan",
        )
    )


def display_endpoints(result):
    table = Table(
        box=None,
        expand=True,
    )

    table.add_column(
        "ENDPOINT",
        style="bold cyan",
    )

    table.add_column(
        "SOURCE",
        style="white",
    )

    table.add_column(
        "STATUS",
        style="white",
    )

    endpoints = result.get(
        "endpoints",
        [],
    )

    if not endpoints:
        table.add_row(
            "None discovered",
            "N/A",
            "N/A",
        )

    for item in endpoints[:50]:
        table.add_row(
            item.get(
                "url",
                "N/A",
            ),
            item.get(
                "source",
                "N/A",
            ),
            str(
                item.get(
                    "status_code",
                    "N/A",
                )
            ),
        )

    console.print(
        Panel(
            table,
            title="[bold cyan]ENDPOINT DISCOVERY[/bold cyan]",
            border_style="cyan",
        )
    )


def display_contacts(result):
    table = Table(
        box=None,
        expand=True,
    )

    table.add_column(
        "TYPE",
        style="bold cyan",
    )

    table.add_column(
        "VALUE",
        style="white",
    )

    emails = result.get(
        "emails",
        [],
    )

    phones = result.get(
        "phones",
        [],
    )

    contact_pages = result.get(
        "contact_pages",
        [],
    )

    for email in emails:
        table.add_row(
            "EMAIL",
            email,
        )

    for phone in phones:
        table.add_row(
            "PHONE",
            phone,
        )

    for page in contact_pages:
        table.add_row(
            "CONTACT PAGE",
            page,
        )

    if not emails and not phones and not contact_pages:
        table.add_row(
            "N/A",
            "No public contact information found",
        )

    console.print(
        Panel(
            table,
            title="[bold cyan]PUBLIC CONTACT INFORMATION[/bold cyan]",
            border_style="cyan",
        )
    )


def display_exposure(result):
    table = Table(
        box=None,
        expand=True,
    )

    table.add_column(
        "RESOURCE",
        style="bold cyan",
    )

    table.add_column(
        "INDICATOR",
        style="white",
    )

    findings = result.get(
        "findings",
        [],
    )

    if not findings:
        table.add_row(
            "N/A",
            "[green]No indicators detected[/green]",
        )

    for item in findings:
        url = item.get(
            "url",
            "N/A",
        )

        for finding in item.get(
            "findings",
            [],
        ):
            table.add_row(
                url,
                finding.get(
                    "type",
                    "UNKNOWN",
                ),
            )

    console.print(
        Panel(
            table,
            title="[bold cyan]PUBLIC EXPOSURE CHECK[/bold cyan]",
            border_style="cyan",
        )
    )


def display_final_summary(
    results,
):
    table = Table(
        box=None,
        expand=True,
    )

    table.add_column(
        "METRIC",
        style="bold cyan",
    )

    table.add_column(
        "VALUE",
        style="white",
    )

    ip_result = results.get(
        "ip",
        {},
    )

    port_result = results.get(
        "ports",
        {},
    )

    technology_result = results.get(
        "technology",
        {},
    )

    endpoint_result = results.get(
        "endpoints",
        {},
    )

    contact_result = results.get(
        "contacts",
        {},
    )

    exposure_result = results.get(
        "exposure",
        {},
    )

    open_ports = [
        item
        for item in port_result.get(
            "ports",
            [],
        )
        if item.get("state") == "open"
    ]

    table.add_row(
        "IP Addresses",
        str(
            len(
                ip_result.get(
                    "all_ips",
                    [],
                )
            )
        ),
    )

    table.add_row(
        "Open Ports",
        str(
            len(open_ports)
        ),
    )

    table.add_row(
        "Technologies",
        str(
            len(
                technology_result.get(
                    "technologies",
                    [],
                )
            )
        ),
    )

    table.add_row(
        "Endpoints",
        str(
            len(
                endpoint_result.get(
                    "endpoints",
                    [],
                )
            )
        ),
    )

    table.add_row(
        "Public Emails",
        str(
            len(
                contact_result.get(
                    "emails",
                    [],
                )
            )
        ),
    )

    table.add_row(
        "Public Phones",
        str(
            len(
                contact_result.get(
                    "phones",
                    [],
                )
            )
        ),
    )

    table.add_row(
        "Exposure Indicators",
        str(
            sum(
                len(
                    item.get(
                        "findings",
                        [],
                    )
                )
                for item in exposure_result.get(
                    "findings",
                    [],
                )
            )
        ),
    )

    console.print(
        Panel(
            table,
            title=(
                "[bold cyan]"
                "SHADOWRECON FINAL SUMMARY"
                "[/bold cyan]"
            ),
            border_style="cyan",
            box=box.DOUBLE,
        )
    )


def run():
    clear_screen()

    show_banner()

    console.print(
        "\n[bold white]"
        "Authorized reconnaissance framework"
        "[/bold white]"
    )

    target_value = ask_target()

    # Target validation happens here.
    try:
        scanner = Scanner(
            target_value
        )
    except Exception as error:
        console.print(
            f"\n[bold red]"
            f"Invalid target: {error}"
            f"[/bold red]"
        )
        return

    # Explicit authorization.
    if not authorization_prompt(
        target_value
    ):
        console.print(
            "\n[bold red]"
            "Authorization not confirmed. "
            "Scan cancelled."
            "[/bold red]"
        )
        return

    try:
        scanner.authorize()
    except PermissionError as error:
        console.print(
            f"\n[bold red]{error}[/bold red]"
        )
        return

    target = scanner.get_target()

    clear_screen()

    show_banner()

    display_target(
        target,
        authorized=True,
    )

    print_section(
        "RECONNAISSANCE STARTED"
    )

    results = {}

    # ---------------------------------------------------------
    # DNS
    # ---------------------------------------------------------

    if target.target_type in (
        "DOMAIN",
        "URL",
    ):
        results["dns"] = safe_run(
            "DNS",
            lambda: scan_dns(
                target.host
            ),
        )

    else:
        results["dns"] = {}

        console.print(
            module_status(
                "DNS",
                "SKIPPED",
            )
        )

    # ---------------------------------------------------------
    # SUBDOMAINS
    # ---------------------------------------------------------

    if target.target_type in (
        "DOMAIN",
        "URL",
    ):
        results["subdomains"] = safe_run(
            "SUBDOMAINS",
            lambda: discover_subdomains(
                target.host
            ),
        )

    else:
        results["subdomains"] = []

        console.print(
            module_status(
                "SUBDOMAINS",
                "SKIPPED",
            )
        )

    # ---------------------------------------------------------
    # HTTP
    # ---------------------------------------------------------

    results["http"] = safe_run(
        "HTTP",
        lambda: scan_http(
            target
        ),
    )

    # ---------------------------------------------------------
    # IP
    # ---------------------------------------------------------

    results["ip"] = safe_run(
        "IP INTELLIGENCE",
        lambda: scan_ip(
            target
        ),
    )

    # ---------------------------------------------------------
    # LOCATION / ASN
    # ---------------------------------------------------------

    ipinfo_token = os.getenv(
        "SHADOWRECON_IPINFO_TOKEN"
    )

    results["location"] = safe_run(
        "LOCATION / ASN",
        lambda: scan_location(
            results["ip"],
            token=ipinfo_token,
        ),
    )

    # ---------------------------------------------------------
    # MAC
    # ---------------------------------------------------------

    results["mac"] = safe_run(
        "MAC INTELLIGENCE",
        lambda: scan_mac(
            results["ip"]
        ),
    )

    # ---------------------------------------------------------
    # PORTS
    # ---------------------------------------------------------

    results["ports"] = safe_run(
        "PORT / SERVICE",
        lambda: scan_ports(
            target.host
        ),
    )

    # ---------------------------------------------------------
    # TECHNOLOGY
    # ---------------------------------------------------------

    results["technology"] = safe_run(
        "TECHNOLOGY",
        lambda: scan_technology(
            target
        ),
    )

    # ---------------------------------------------------------
    # SECURITY HEADERS
    # ---------------------------------------------------------

    results["headers"] = safe_run(
        "SECURITY HEADERS",
        lambda: scan_headers(
            target
        ),
    )

    # ---------------------------------------------------------
    # ENDPOINTS
    # ---------------------------------------------------------

    results["endpoints"] = safe_run(
        "ENDPOINT DISCOVERY",
        lambda: scan_endpoints(
            target
        ),
    )

    # ---------------------------------------------------------
    # PUBLIC CONTACT
    # ---------------------------------------------------------

    results["contacts"] = safe_run(
        "PUBLIC CONTACT",
        lambda: scan_contact_info(
            target
        ),
    )

    # ---------------------------------------------------------
    # PUBLIC EXPOSURE
    # ---------------------------------------------------------

    results["exposure"] = safe_run(
        "PUBLIC EXPOSURE",
        lambda: scan_exposure(
            target
        ),
    )

    # ---------------------------------------------------------
    # RESULTS
    # ---------------------------------------------------------

    print_section(
        "RECONNAISSANCE RESULTS"
    )

    if results.get("dns"):
        display_dns(
            results["dns"]
        )

    if isinstance(
        results.get("subdomains"),
        list,
    ):
        display_subdomains(
            results["subdomains"]
        )

    if results.get("http"):
        display_http(
            results["http"]
        )

    if results.get("ip"):
        display_ip(
            results["ip"]
        )

    if isinstance(
        results.get("location"),
        list,
    ):
        display_location(
            results["location"]
        )

    if isinstance(
        results.get("ports"),
        dict,
    ):
        display_ports(
            results["ports"]
        )

    if isinstance(
        results.get("technology"),
        dict,
    ):
        display_technology(
            results["technology"]
        )

    if isinstance(
        results.get("headers"),
        dict,
    ):
        display_headers(
            results["headers"]
        )

    if isinstance(
        results.get("endpoints"),
        dict,
    ):
        display_endpoints(
            results["endpoints"]
        )

    if isinstance(
        results.get("contacts"),
        dict,
    ):
        display_contacts(
            results["contacts"]
        )

    if isinstance(
        results.get("exposure"),
        dict,
    ):
        display_exposure(
            results["exposure"]
        )

    display_final_summary(
        results
    )

    console.print(
        "\n[bold cyan]"
        "SHADOWRECON SCAN COMPLETE"
        "[/bold cyan]"
    )


if __name__ == "__main__":
    run()
