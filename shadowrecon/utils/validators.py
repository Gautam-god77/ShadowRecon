import ipaddress
import re
from urllib.parse import urlparse


DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)


def is_valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_private_ip(value):
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def is_valid_domain(value):
    return bool(DOMAIN_REGEX.match(value))


def normalize_url(value):
    if not value.startswith(("http://", "https://")):
        value = "https://" + value

    parsed = urlparse(value)

    if not parsed.hostname:
        raise ValueError("Invalid URL")

    return value


def detect_target_type(value):

    value = value.strip()

    if is_valid_ip(value):
        return "IP"

    if value.startswith(("http://", "https://")):
        parsed = urlparse(value)

        if parsed.hostname and is_valid_ip(parsed.hostname):
            return "URL-IP"

        if parsed.hostname and is_valid_domain(parsed.hostname):
            return "URL"

        raise ValueError("Invalid URL")

    if is_valid_domain(value):
        return "DOMAIN"

    raise ValueError("Invalid domain, IP address, or URL")
