import requests


USER_AGENT = (
    "ShadowRecon/1.0 "
    "(Authorized Security Reconnaissance)"
)


SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "name": "HSTS",
        "description": "Enforces HTTPS connections.",
    },
    "Content-Security-Policy": {
        "name": "CSP",
        "description": "Controls allowed content sources.",
    },
    "X-Frame-Options": {
        "name": "X-Frame-Options",
        "description": "Helps prevent clickjacking.",
    },
    "X-Content-Type-Options": {
        "name": "X-Content-Type-Options",
        "description": "Helps prevent MIME sniffing.",
    },
    "Referrer-Policy": {
        "name": "Referrer-Policy",
        "description": "Controls referrer information.",
    },
    "Permissions-Policy": {
        "name": "Permissions-Policy",
        "description": "Controls browser feature permissions.",
    },
    "Cross-Origin-Opener-Policy": {
        "name": "COOP",
        "description": "Controls cross-origin window relationships.",
    },
    "Cross-Origin-Resource-Policy": {
        "name": "CORP",
        "description": "Controls cross-origin resource loading.",
    },
    "Cross-Origin-Embedder-Policy": {
        "name": "COEP",
        "description": "Controls cross-origin resource embedding.",
    },
}


def create_session():

    session = requests.Session()

    session.headers.update(
        {
            "User-Agent": USER_AGENT
        }
    )

    return session


def normalize_headers(response):
    """
    Convert response headers into a normal dictionary.
    """

    return {
        key.lower(): value.strip()
        for key, value in response.headers.items()
    }


def inspect_security_headers(headers):
    """
    Check configured security headers.
    """

    results = []

    for header, metadata in SECURITY_HEADERS.items():

        value = headers.get(
            header.lower()
        )

        if value:

            results.append(
                {
                    "header": header,
                    "name": metadata["name"],
                    "status": "PRESENT",
                    "value": value,
                    "description": metadata[
                        "description"
                    ],
                }
            )

        else:

            results.append(
                {
                    "header": header,
                    "name": metadata["name"],
                    "status": "MISSING",
                    "value": None,
                    "description": metadata[
                        "description"
                    ],
                }
            )

    return results


def scan_headers(target):
    """
    Inspect HTTP security headers from a web target.

    This module does not attempt to exploit missing headers.
    """

    result = {
        "target": target,
        "url": None,
        "status": "NOT STARTED",
        "status_code": None,
        "headers": [],
        "raw_headers": {},
        "error": None,
    }

    if not target:

        result["status"] = "INVALID TARGET"

        result["error"] = (
            "Target is empty."
        )

        return result

    # --------------------------------------------------------
    # Target URL
    # --------------------------------------------------------

    if hasattr(target, "url"):

        url = target.url

        if not url:

            url = (
                f"https://{target.host}"
            )

    else:

        url = str(target)

        if not url.startswith(
            (
                "http://",
                "https://",
            )
        ):

            url = (
                "https://"
                + url
            )

    result["url"] = url

    session = create_session()

    try:

        response = session.get(
            url,
            timeout=10,
            allow_redirects=True,
        )

        result["url"] = response.url

        result["status_code"] = (
            response.status_code
        )

        normalized = normalize_headers(
            response
        )

        result["raw_headers"] = normalized

        result["headers"] = (
            inspect_security_headers(
                normalized
            )
        )

        result["status"] = "COMPLETE"

        return result

    except requests.RequestException as error:

        result["status"] = "ERROR"

        result["error"] = str(error)

        return result

    except Exception as error:

        result["status"] = "ERROR"

        result["error"] = str(error)

        return result


def get_present_headers(scan_result):
    """
    Return only headers that are present.
    """

    return [
        item
        for item in scan_result.get(
            "headers",
            []
        )
        if item.get("status")
        == "PRESENT"
    ]


def get_missing_headers(scan_result):
    """
    Return only headers that are missing.
    """

    return [
        item
        for item in scan_result.get(
            "headers",
            []
        )
        if item.get("status")
        == "MISSING"
    ]


def count_present_headers(scan_result):

    return len(
        get_present_headers(
            scan_result
        )
    )


def count_missing_headers(scan_result):

    return len(
        get_missing_headers(
            scan_result
        )
    )
