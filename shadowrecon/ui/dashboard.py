from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box


console = Console()


def _value(data, key, default="N/A"):
    if not isinstance(data, dict):
        return default

    return data.get(
        key,
        default,
    )


def build_module_status(
    dns_result=None,
    subdomain_result=None,
    http_result=None,
    ip_result=None,
    mac_result=None,
    port_result=None,
    technology_result=None,
    headers_result=None,
    endpoint_result=None,
    contact_result=None,
    exposure_result=None,
):
    modules = []

    def add_module(
        name,
        result,
        result_text,
    ):
        status = _value(
            result,
            "status",
            "NOT RUN",
        )

        modules.append({
            "module": name,
            "status": status,
            "result": result_text,
        })

    dns_records = 0

    if isinstance(dns_result, dict):
        for records in dns_result.values():
            if isinstance(records, list):
                dns_records += len(records)

    add_module(
        "DNS",
        {
            "status": (
                "COMPLETE"
                if dns_result is not None
                else "NOT RUN"
            )
        },
        f"{dns_records} records",
    )

    subdomain_count = 0

    if isinstance(subdomain_result, dict):
        subdomain_count = len(
            subdomain_result.get(
                "subdomains",
                subdomain_result.get(
                    "results",
                    [],
                ),
            )
        )

    add_module(
        "SUBDOMAINS",
        subdomain_result,
        f"{subdomain_count} discovered",
    )

    http_status = "N/A"

    if isinstance(http_result, dict):
        http_status = _value(
            http_result,
            "status_code",
            "N/A",
        )

    add_module(
        "HTTP",
        {
            "status": (
                "COMPLETE"
                if http_result is not None
                else "NOT RUN"
            )
        },
        f"{http_status}",
    )

    ip_count = 0

    if isinstance(ip_result, dict):
        ip_count = len(
            ip_result.get(
                "all_ips",
                [],
            )
        )

    add_module(
        "IP",
        ip_result,
        f"{ip_count} addresses",
    )

    mac_count = 0

    if isinstance(mac_result, list):
        mac_count = len(
            [
                item
                for item in mac_result
                if item.get("mac")
            ]
        )

    add_module(
        "MAC",
        {
            "status": (
                "COMPLETE"
                if mac_result is not None
                else "NOT RUN"
            )
        },
        f"{mac_count} discovered",
    )

    open_ports = 0

    if isinstance(port_result, dict):
        open_ports = len([
            item
            for item in port_result.get(
                "ports",
                [],
            )
            if item.get("state") == "open"
        ])

    add_module(
        "PORTS",
        port_result,
        f"{open_ports} open",
    )

    technology_count = 0

    if isinstance(
        technology_result,
        dict,
    ):
        technology_count = len(
            technology_result.get(
                "technologies",
                [],
            )
        )

    add_module(
        "TECHNOLOGY",
        technology_result,
        f"{technology_count} detected",
    )

    present_headers = 0

    if isinstance(
        headers_result,
        dict,
    ):
        present_headers = len([
            item
            for item in headers_result.get(
                "headers",
                [],
            )
            if item.get("status") == "PRESENT"
        ])

    add_module(
        "HEADERS",
        headers_result,
        f"{present_headers} present",
    )

    endpoint_count = 0

    if isinstance(
        endpoint_result,
        dict,
    ):
        endpoint_count = len(
            endpoint_result.get(
                "endpoints",
                [],
            )
        )

    add_module(
        "ENDPOINTS",
        endpoint_result,
        f"{endpoint_count} found",
    )

    email_count = 0
    phone_count = 0

    if isinstance(
        contact_result,
        dict,
    ):
        email_count = len(
            contact_result.get(
                "emails",
                [],
            )
        )

        phone_count = len(
            contact_result.get(
                "phones",
                [],
            )
        )

    add_module(
        "CONTACT",
        contact_result,
        f"{email_count} emails / {phone_count} phones",
    )

    exposure_count = 0

    if isinstance(
        exposure_result,
        dict,
    ):
        for item in exposure_result.get(
            "findings",
            [],
        ):
            exposure_count += len(
                item.get(
                    "findings",
                    [],
                )
            )

    add_module(
        "EXPOSURE",
        exposure_result,
        f"{exposure_count} indicators",
    )

    return modules


def target_information_panel(
    target,
    authorized=False,
):
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
        "Target",
        getattr(
            target,
            "original",
            "N/A",
        ),
    )

    table.add_row(
        "Type",
        getattr(
            target,
            "target_type",
            "N/A",
        ),
    )

    table.add_row(
        "Host",
        getattr(
            target,
            "host",
            "N/A",
        ),
    )

    if authorized:
        authorization = (
            "[bold green]"
            "CONFIRMED"
            "[/bold green]"
        )
    else:
        authorization = (
            "[bold red]"
            "NOT CONFIRMED"
            "[/bold red]"
        )

    table.add_row(
        "Authorization",
        authorization,
    )

    return Panel(
        table,
        title=(
            "[bold cyan]"
            "TARGET INFORMATION"
            "[/bold cyan]"
        ),
        border_style="cyan",
        box=box.ROUNDED,
    )


def final_summary_panel(
    module_results,
):
    complete = len([
        item
        for item in module_results
        if item.get("status") == "COMPLETE"
    ])

    total = len(module_results)

    table = Table(
        box=None,
        expand=True,
    )

    table.add_column(
        "SUMMARY",
        style="bold cyan",
    )

    table.add_column(
        "VALUE",
        style="white",
    )

    table.add_row(
        "Modules Completed",
        f"{complete}/{total}",
    )

    table.add_row(
        "Framework Status",
        (
            "[bold green]READY[/bold green]"
            if complete == total
            else "[bold yellow]PARTIAL[/bold yellow]"
        ),
    )

    return Panel(
        table,
        title=(
            "[bold cyan]"
            "SHADOWRECON SUMMARY"
            "[/bold cyan]"
        ),
        border_style="cyan",
        box=box.DOUBLE,
    )
