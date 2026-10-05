import ipaddress
import socket


def classify_ip(address):
    """
    Classify an IP address as PUBLIC, PRIVATE, LOOPBACK,
    LINK-LOCAL, or RESERVED.
    """

    try:
        ip = ipaddress.ip_address(address)

        if ip.is_private:
            return "PRIVATE"

        if ip.is_loopback:
            return "LOOPBACK"

        if ip.is_link_local:
            return "LINK-LOCAL"

        if ip.is_reserved:
            return "RESERVED"

        if ip.is_global:
            return "PUBLIC"

        return "OTHER"

    except ValueError:
        return "INVALID"


def resolve_target(host):
    """
    Resolve hostname into IPv4 and IPv6 addresses.

    Returns a dictionary containing IP information.
    """

    result = {
        "hostname": host,
        "ipv4": [],
        "ipv6": [],
        "all_ips": [],
        "classifications": {},
        "error": None,
    }

    try:

        address_info = socket.getaddrinfo(
            host,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        )

        for item in address_info:

            family = item[0]
            sockaddr = item[4]

            address = sockaddr[0]

            if address not in result["all_ips"]:

                result["all_ips"].append(
                    address
                )

            if family == socket.AF_INET:

                if address not in result["ipv4"]:

                    result["ipv4"].append(
                        address
                    )

            elif family == socket.AF_INET6:

                if address not in result["ipv6"]:

                    result["ipv6"].append(
                        address
                    )

        for address in result["all_ips"]:

            result["classifications"][address] = (
                classify_ip(address)
            )

    except socket.gaierror as error:

        result["error"] = str(error)

    except Exception as error:

        result["error"] = str(error)

    return result


def scan_ip(target):
    """
    Perform IP reconnaissance for a Target object.
    """

    host = target.host

    # --------------------------------------------------------
    # Direct IP target
    # --------------------------------------------------------

    try:

        ipaddress.ip_address(host)

        classification = classify_ip(host)

        result = {
            "hostname": None,
            "ipv4": [],
            "ipv6": [],
            "all_ips": [host],
            "classifications": {
                host: classification
            },
            "error": None,
        }

        if ":" in host:

            result["ipv6"].append(host)

        else:

            result["ipv4"].append(host)

        return result

    except ValueError:

        pass

    # --------------------------------------------------------
    # Domain / URL hostname
    # --------------------------------------------------------

    return resolve_target(host)
