import ipaddress
import shutil
import subprocess
import xml.etree.ElementTree as ET


DEFAULT_PORTS = (
    "21,22,23,25,53,80,110,111,135,139,143,443,"
    "445,993,995,1433,1521,3306,3389,5432,5900,6379,"
    "8000,8080,8443"
)


def is_public_or_private_target(target):
    """
    Validate that the supplied target is a valid hostname or IP.
    """

    target = target.strip()

    if not target:
        return False

    try:
        ipaddress.ip_address(target)
        return True

    except ValueError:
        pass

    # Basic hostname validation
    if len(target) > 253:
        return False

    if "." not in target:
        return False

    return True


def check_nmap():
    """
    Check whether Nmap is installed.
    """

    return shutil.which("nmap") is not None


def parse_nmap_xml(xml_data):
    """
    Parse Nmap XML output into clean Python dictionaries.
    """

    results = []

    try:

        root = ET.fromstring(
            xml_data
        )

    except ET.ParseError:

        return results

    for host in root.findall("host"):

        address_element = host.find("address")

        host_address = (
            address_element.get("addr")
            if address_element is not None
            else "N/A"
        )

        ports_element = host.find("ports")

        if ports_element is None:
            continue

        for port in ports_element.findall("port"):

            port_id = port.get(
                "portid",
                "N/A"
            )

            protocol = port.get(
                "protocol",
                "N/A"
            )

            state_element = port.find("state")
            service_element = port.find("service")

            state = "unknown"
            service = "unknown"
            product = "N/A"
            version = "N/A"
            extrainfo = "N/A"

            if state_element is not None:

                state = state_element.get(
                    "state",
                    "unknown"
                )

            if service_element is not None:

                service = service_element.get(
                    "name",
                    "unknown"
                )

                product = service_element.get(
                    "product",
                    "N/A"
                )

                version = service_element.get(
                    "version",
                    "N/A"
                )

                extrainfo = service_element.get(
                    "extrainfo",
                    "N/A"
                )

            results.append(
                {
                    "host": host_address,
                    "port": int(port_id)
                    if port_id.isdigit()
                    else port_id,
                    "protocol": protocol,
                    "state": state,
                    "service": service,
                    "product": product,
                    "version": version,
                    "extrainfo": extrainfo,
                }
            )

    return results


def scan_ports(
    target,
    ports=DEFAULT_PORTS,
    timing="T3",
):
    """
    Perform controlled Nmap TCP service discovery.

    -sT : TCP connect scan
    -sV : Service/version detection
    -Pn : Do not depend on ICMP host discovery
    -T3 : Moderate timing
    -oX - : XML output to stdout
    """

    target_value = target.strip()

    result = {
        "target": target_value,
        "scanner": "nmap",
        "status": "NOT STARTED",
        "ports": [],
        "error": None,
    }

    if not is_public_or_private_target(
        target_value
    ):

        result["status"] = "INVALID TARGET"

        result["error"] = (
            "Invalid hostname or IP address."
        )

        return result

    if not check_nmap():

        result["status"] = "NMAP NOT FOUND"

        result["error"] = (
            "Nmap is not installed or not available in PATH."
        )

        return result

    command = [
        "nmap",
        "-sT",
        "-sV",
        "-Pn",
        f"-{timing}",
        "-p",
        ports,
        "-oX",
        "-",
        target_value,
    ]

    try:

        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )

    except subprocess.TimeoutExpired:

        result["status"] = "TIMEOUT"

        result["error"] = (
            "Nmap scan exceeded the 180 second timeout."
        )

        return result

    except Exception as error:

        result["status"] = "ERROR"

        result["error"] = str(error)

        return result

    if process.returncode != 0:

        result["status"] = "NMAP ERROR"

        result["error"] = (
            process.stderr.strip()
            or "Nmap returned a non-zero exit code."
        )

        return result

    parsed_results = parse_nmap_xml(
        process.stdout
    )

    result["status"] = "COMPLETE"

    result["ports"] = parsed_results

    return result


def get_open_ports(scan_result):
    """
    Return only ports whose state is open.
    """

    return [
        item
        for item in scan_result.get(
            "ports",
            []
        )
        if item.get("state") == "open"
    ]


def count_open_ports(scan_result):
    """
    Count open ports.
    """

    return len(
        get_open_ports(
            scan_result
        )
    )
