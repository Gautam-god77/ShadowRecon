import ipaddress

import requests


IPINFO_LITE_URL = (
    "https://api.ipinfo.io/lite/{ip}"
)


def is_public_ip(ip):
    """
    Return True only for globally routable/public IPs.
    """

    try:

        address = ipaddress.ip_address(ip)

        return address.is_global

    except ValueError:

        return False


def lookup_ip_location(ip, token=None):
    """
    Lookup public IP location and ASN information.

    IPinfo Lite provides country-level and ASN data.
    """

    result = {
        "ip": ip,
        "status": "N/A",
        "country": "N/A",
        "country_code": "N/A",
        "continent": "N/A",
        "asn": "N/A",
        "organization": "N/A",
        "city": "N/A",
        "region": "N/A",
        "error": None,
    }

    if not is_public_ip(ip):

        result["status"] = "NOT PUBLIC"

        return result

    if not token:

        result["status"] = "TOKEN REQUIRED"

        result["error"] = (
            "Set SHADOWRECON_IPINFO_TOKEN "
            "to enable IPinfo lookup."
        )

        return result

    url = IPINFO_LITE_URL.format(
        ip=ip
    )

    try:

        response = requests.get(
            url,
            params={
                "token": token
            },
            timeout=8,
        )

        response.raise_for_status()

        data = response.json()

        result["status"] = "SUCCESS"

        result["country"] = data.get(
            "country",
            "N/A"
        )

        result["country_code"] = data.get(
            "country_code",
            "N/A"
        )

        result["continent"] = data.get(
            "continent",
            "N/A"
        )

        result["asn"] = data.get(
            "asn",
            "N/A"
        )

        result["organization"] = data.get(
            "as_name",
            "N/A"
        )

        return result

    except requests.RequestException as error:

        result["status"] = "ERROR"

        result["error"] = str(error)

        return result

    except ValueError as error:

        result["status"] = "ERROR"

        result["error"] = str(error)

        return result


def scan_location(ip_result, token=None):
    """
    Process all discovered IPs.

    Private IPs are never sent for geolocation.
    """

    results = []

    for ip in ip_result.get(
        "all_ips",
        []
    ):

        result = lookup_ip_location(
            ip,
            token=token,
        )

        results.append(
            result
        )

    return results
