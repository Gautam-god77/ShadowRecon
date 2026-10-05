import re
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


USER_AGENT = (
    "ShadowRecon/1.0 "
    "(Authorized Security Reconnaissance)"
)


DEFAULT_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/security.txt",
    "/favicon.ico",
    "/manifest.json",
    "/.well-known/",
]


def create_session():
    session = requests.Session()

    session.headers.update(
        {
            "User-Agent": USER_AGENT
        }
    )

    return session


def normalize_base_url(target):
    """
    Convert a Target object or string into a base URL.
    """

    if hasattr(target, "url"):

        if target.url:
            return target.url.rstrip("/")

        host = target.host

        return (
            f"https://{host}"
        )

    value = str(target).strip()

    if not value.startswith(
        (
            "http://",
            "https://",
        )
    ):

        value = (
            "https://"
            + value
        )

    return value.rstrip("/")


def is_same_host(base_url, target_url):
    """
    Check whether a discovered URL belongs to
    the original target host.
    """

    try:

        base_host = (
            urlparse(base_url)
            .hostname
        )

        target_host = (
            urlparse(target_url)
            .hostname
        )

        if not base_host or not target_host:
            return False

        return (
            base_host.lower()
            == target_host.lower()
        )

    except Exception:

        return False


def clean_url(url):
    """
    Remove fragments from URLs.
    """

    try:

        parsed = urlparse(url)

        return parsed._replace(
            fragment=""
        ).geturl()

    except Exception:

        return url


def add_endpoint(
    endpoints,
    url,
    source,
    status_code=None,
    content_type=None,
):
    """
    Add an endpoint once.
    """

    url = clean_url(url)

    for endpoint in endpoints:

        if endpoint["url"] == url:

            return

    endpoints.append(
        {
            "url": url,
            "source": source,
            "status_code": status_code,
            "content_type": content_type,
        }
    )


def discover_common_paths(
    session,
    base_url,
    endpoints,
):
    """
    Check a small list of known public files/directories.
    """

    for path in DEFAULT_PATHS:

        url = urljoin(
            base_url + "/",
            path.lstrip("/"),
        )

        try:

            response = session.get(
                url,
                timeout=8,
                allow_redirects=True,
            )

            # Only record actual HTTP responses.
            if response.status_code < 500:

                add_endpoint(
                    endpoints,
                    response.url,
                    "COMMON PATH",
                    response.status_code,
                    response.headers.get(
                        "Content-Type"
                    ),
                )

        except requests.RequestException:

            continue


def discover_robots(
    session,
    base_url,
    endpoints,
):
    """
    Fetch robots.txt and record the endpoint.

    Disallowed paths are extracted as public references,
    not automatically scanned.
    """

    url = urljoin(
        base_url + "/",
        "robots.txt",
    )

    try:

        response = session.get(
            url,
            timeout=8,
            allow_redirects=True,
        )

        if response.status_code == 200:

            add_endpoint(
                endpoints,
                response.url,
                "ROBOTS.TXT",
                response.status_code,
                response.headers.get(
                    "Content-Type"
                ),
            )

            paths = []

            for line in response.text.splitlines():

                line = line.strip()

                if not line:
                    continue

                if line.lower().startswith(
                    "disallow:"
                ):

                    path = line.split(
                        ":",
                        1
                    )[1].strip()

                    if path:

                        paths.append(path)

                elif line.lower().startswith(
                    "allow:"
                ):

                    path = line.split(
                        ":",
                        1
                    )[1].strip()

                    if path:

                        paths.append(path)

            for path in paths:

                endpoint_url = urljoin(
                    base_url + "/",
                    path.lstrip("/"),
                )

                if is_same_host(
                    base_url,
                    endpoint_url,
                ):

                    add_endpoint(
                        endpoints,
                        endpoint_url,
                        "ROBOTS REFERENCE",
                    )

    except requests.RequestException:

        pass


def discover_sitemap(
    session,
    base_url,
    endpoints,
):
    """
    Fetch sitemap.xml and extract URLs.
    """

    url = urljoin(
        base_url + "/",
        "sitemap.xml",
    )

    try:

        response = session.get(
            url,
            timeout=8,
            allow_redirects=True,
        )

        if response.status_code != 200:
            return

        add_endpoint(
            endpoints,
            response.url,
            "SITEMAP.XML",
            response.status_code,
            response.headers.get(
                "Content-Type"
            ),
        )

        content = response.text

        # Basic XML URL extraction.
        matches = re.findall(
            r"<loc>\s*(.*?)\s*</loc>",
            content,
            flags=re.I | re.S,
        )

        for discovered_url in matches:

            discovered_url = (
                discovered_url.strip()
            )

            if not discovered_url:
                continue

            if is_same_host(
                base_url,
                discovered_url,
            ):

                add_endpoint(
                    endpoints,
                    discovered_url,
                    "SITEMAP REFERENCE",
                )

    except requests.RequestException:

        pass


def discover_html_links(
    response,
    base_url,
    endpoints,
):
    """
    Extract same-host links from HTML.
    """

    content_type = response.headers.get(
        "Content-Type",
        "",
    ).lower()

    if "text/html" not in content_type:
        return

    try:

        soup = BeautifulSoup(
            response.text,
            "html.parser",
        )

    except Exception:

        return

    for anchor in soup.find_all(
        "a",
        href=True,
    ):

        href = anchor.get(
            "href"
        )

        if not href:
            continue

        href = href.strip()

        if href.startswith(
            (
                "#",
                "mailto:",
                "javascript:",
                "tel:",
            )
        ):
            continue

        absolute_url = urljoin(
            response.url,
            href,
        )

        absolute_url = clean_url(
            absolute_url
        )

        if is_same_host(
            base_url,
            absolute_url,
        ):

            add_endpoint(
                endpoints,
                absolute_url,
                "HTML LINK",
            )


def discover_javascript(
    response,
    base_url,
    endpoints,
):
    """
    Extract JavaScript references from HTML.
    """

    content_type = response.headers.get(
        "Content-Type",
        "",
    ).lower()

    if "text/html" not in content_type:
        return

    try:

        soup = BeautifulSoup(
            response.text,
            "html.parser",
        )

    except Exception:

        return

    for script in soup.find_all(
        "script",
        src=True,
    ):

        src = script.get(
            "src"
        )

        if not src:
            continue

        js_url = urljoin(
            response.url,
            src,
        )

        js_url = clean_url(
            js_url
        )

        if is_same_host(
            base_url,
            js_url,
        ):

            add_endpoint(
                endpoints,
                js_url,
                "JAVASCRIPT",
            )


def scan_endpoints(target):
    """
    Perform passive/public endpoint discovery.
    """

    result = {
        "target": str(target),
        "base_url": None,
        "status": "NOT STARTED",
        "endpoints": [],
        "error": None,
    }

    if not target:

        result["status"] = "INVALID TARGET"

        result["error"] = (
            "Target is empty."
        )

        return result

    base_url = normalize_base_url(
        target
    )

    result["base_url"] = base_url

    session = create_session()

    endpoints = []

    try:

        # ----------------------------------------------------
        # Main page
        # ----------------------------------------------------

        response = session.get(
            base_url,
            timeout=10,
            allow_redirects=True,
        )

        if response.status_code < 500:

            add_endpoint(
                endpoints,
                response.url,
                "MAIN PAGE",
                response.status_code,
                response.headers.get(
                    "Content-Type"
                ),
            )

        # ----------------------------------------------------
        # HTML links
        # ----------------------------------------------------

        discover_html_links(
            response,
            base_url,
            endpoints,
        )

        # ----------------------------------------------------
        # JavaScript
        # ----------------------------------------------------

        discover_javascript(
            response,
            base_url,
            endpoints,
        )

        # ----------------------------------------------------
        # robots.txt
        # ----------------------------------------------------

        discover_robots(
            session,
            base_url,
            endpoints,
        )

        # ----------------------------------------------------
        # sitemap.xml
        # ----------------------------------------------------

        discover_sitemap(
            session,
            base_url,
            endpoints,
        )

        # ----------------------------------------------------
        # Common public paths
        # ----------------------------------------------------

        discover_common_paths(
            session,
            base_url,
            endpoints,
        )

        result["status"] = "COMPLETE"

        result["endpoints"] = endpoints

        return result

    except requests.RequestException as error:

        result["status"] = "ERROR"

        result["error"] = str(error)

        return result

    except Exception as error:

        result["status"] = "ERROR"

        result["error"] = str(error)

        return result


def get_endpoints_by_source(
    scan_result,
    source,
):
    """
    Filter discovered endpoints by source.
    """

    return [
        item
        for item in scan_result.get(
            "endpoints",
            []
        )
        if item.get("source")
        == source
    ]


def count_endpoints(scan_result):
    return len(
        scan_result.get(
            "endpoints",
            []
        )
    )
