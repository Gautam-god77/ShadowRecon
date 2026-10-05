import ipaddress
import re
import subprocess


MAC_REGEX = re.compile(
    r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"
)


def is_valid_mac(mac):
    """
    Check whether a MAC address has a valid format.
    """

    if not mac:
        return False

    return bool(
        MAC_REGEX.match(
            mac.strip()
        )
    )


def is_private_ip(ip):
    """
    Check whether an IP belongs to a private network.
    """

    try:

        address = ipaddress.ip_address(ip)

        return address.is_private

    except ValueError:

        return False


def normalize_mac(mac):
    """
    Normalize MAC address format.
    """

    if not mac:
        return None

    mac = mac.strip().lower()

    if is_valid_mac(mac):

        return mac

    return None


def lookup_linux_neighbor(ip):
    """
    Look up a target IP in the Linux neighbor table.

    Uses:
        ip neigh show <IP>

    This does NOT perform a broad network scan.
    """

    try:

        process = subprocess.run(
            [
                "ip",
                "neigh",
                "show",
                ip,
            ],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )

        output = process.stdout.strip()

        if not output:

            return {
                "ip": ip,
                "mac": None,
                "state": "NOT FOUND",
                "source": "LINUX NEIGHBOR TABLE",
            }

        parts = output.split()

        mac = None
        state = "UNKNOWN"

        for index, part in enumerate(parts):

            normalized = normalize_mac(part)

            if normalized:

                mac = normalized

            if part.upper() in (
                "REACHABLE",
                "STALE",
                "DELAY",
                "PROBE",
                "FAILED",
                "NOARP",
                "PERMANENT",
                "INCOMPLETE",
                "NONE",
            ):

                state = part.upper()

        if mac:

            return {
                "ip": ip,
                "mac": mac,
                "state": state,
                "source": "LINUX NEIGHBOR TABLE",
            }

        return {
            "ip": ip,
            "mac": None,
            "state": state,
            "source": "LINUX NEIGHBOR TABLE",
        }

    except subprocess.TimeoutExpired:

        return {
            "ip": ip,
            "mac": None,
            "state": "TIMEOUT",
            "source": "LINUX NEIGHBOR TABLE",
        }

    except FileNotFoundError:

        return {
            "ip": ip,
            "mac": None,
            "state": "IP COMMAND NOT FOUND",
            "source": "N/A",
        }

    except Exception as error:

        return {
            "ip": ip,
            "mac": None,
            "state": "ERROR",
            "source": str(error),
        }


def lookup_proc_arp(ip):
    """
    Fallback lookup using /proc/net/arp.

    Mainly useful for IPv4 LAN targets.
    """

    try:

        with open(
            "/proc/net/arp",
            "r",
            encoding="utf-8",
        ) as file:

            lines = file.readlines()

        for line in lines[1:]:

            parts = line.split()

            if len(parts) < 4:
                continue

            arp_ip = parts[0]
            flags = parts[2]
            mac = normalize_mac(parts[3])

            if arp_ip == ip and mac:

                return {
                    "ip": ip,
                    "mac": mac,
                    "state": f"ARP FLAGS {flags}",
                    "source": "/proc/net/arp",
                }

    except FileNotFoundError:

        pass

    except Exception:

        pass

    return None


def lookup_mac(ip):
    """
    Perform a MAC lookup for a single IP.

    Public/remote IPs are not expected to expose
    their MAC address to the scanning machine.
    """

    try:

        address = ipaddress.ip_address(ip)

    except ValueError:

        return {
            "ip": ip,
            "mac": None,
            "state": "INVALID IP",
            "source": "N/A",
        }

    # --------------------------------------------------------
    # Public Internet IP
    # --------------------------------------------------------

    if not address.is_private:

        return {
            "ip": ip,
            "mac": None,
            "state": "REMOTE",
            "source": "N/A",
        }

    # --------------------------------------------------------
    # Local/private IP
    # --------------------------------------------------------

    result = lookup_linux_neighbor(ip)

    if result.get("mac"):

        return result

    # --------------------------------------------------------
    # Fallback
    # --------------------------------------------------------

    fallback = lookup_proc_arp(ip)

    if fallback:

        return fallback

    return result


def scan_mac(ip_result):
    """
    Scan MAC information for IPs already discovered
    by ShadowRecon.

    No broad ARP/network sweep is performed.
    """

    results = []

    ips = ip_result.get(
        "all_ips",
        [],
    )

    for ip in ips:

        result = lookup_mac(ip)

        results.append(
            result
        )

    return results
