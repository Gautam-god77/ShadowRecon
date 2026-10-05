import re
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


USER_AGENT = (
    "ShadowRecon/1.0 "
    "(Authorized Security Reconnaissance)"
)


EXPOSURE_PATTERNS = {
    "PRIVATE_KEY_HEADER": re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        re.I,
    ),
    "AWS_ACCESS_KEY_ID": re.compile(
        r"\bAKIA[0-9A-Z]{16}\b"
    ),
    "GENERIC_API_KEY": re.compile(
        r"\b(?:api[_-]?key|apikey)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}",
        re.I,
    ),
    "GENERIC_SECRET": re.compile(
        r"\b(?:secret|client[_-]?secret)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}",
        re.I,
    ),
    "PASSWORD_ASSIGNMENT": re.compile(
        r"\b(?:password|passwd|pwd)\s*[:=]\s*['\"]?[^\s'\"<>]{8,}",
        re.I,
    ),
    "BEARER_TOKEN": re.compile(
        r"\bBearer\s+[A-Za-z0-9\-._~+/]+=*",
        re.I,
    ),
}


PUBLIC_FILES = [
    "/robots.txt",
    "/security.txt",
    "/.well-known/security.txt",
    "/sitemap.xml",
]


def create_session():
    session = requests.Session()

    session.headers.update({
        "User-Agent": USER_AGENT
    })

    return session


def normalize_base_url(target):
    if hasattr(target, "url"):
        if target.url:
            return target.url.rstrip("/")

        return f"https://{target.host}"

    value = str(target).strip()

    if not value.startswith(("http://", "https://")):
        value = "https://" + value

    return value.rstrip("/")


def is_same_host(base_url, target_url):
    try:
        base_host = urlparse(base_url).hostname
        target_host = urlparse(target_url).hostname

        if not base_host or not target_host:
            return False

        return (
            base_host.lower()
            == target_host.lower()
        )

    except Exception:
        return False


def redact_match(value):
    if not value:
        return "[REDACTED]"

    if len(value) <= 8:
        return "[REDACTED]"

    return (
        value[:4]
        + "..."
        + value[-4:]
    )


def scan_text_for_exposure(text):
    findings = []

    if not text:
        return findings

    for name, pattern in EXPOSURE_PATTERNS.items():
        matches = pattern.findall(text)

        if not matches:
            continue

        findings.append({
            "type": name,
            "count": len(matches),
            "evidence": (
                "Potential sensitive-data "
                "pattern detected; value redacted."
            ),
        })

    return findings


def extract_public_document_links(
    response,
    base_url,
):
    links = []

    content_type = response.headers.get(
        "Content-Type",
        "",
    ).lower()

    if "text/html" not in content_type:
        return links

    try:
        soup = BeautifulSoup(
            response.text,
            "html.parser",
        )
    except Exception:
        return links

    document_extensions = (
        ".txt",
        ".log",
        ".json",
        ".xml",
        ".yaml",
        ".yml",
        ".conf",
        ".config",
        ".env",
        ".ini",
        ".bak",
        ".old",
    )

    for link in soup.find_all(
        "a",
        href=True,
    ):
        href = link.get("href", "").strip()

        if not href:
            continue

        if href.startswith((
            "#",
            "mailto:",
            "tel:",
            "javascript:",
        )):
            continue

        absolute_url = urljoin(
            response.url,
            href,
        )

        if not is_same_host(
            base_url,
            absolute_url,
        ):
            continue

        path = urlparse(
            absolute_url
        ).path.lower()

        if path.endswith(
            document_extensions
        ):
            if absolute_url not in links:
                links.append(
                    absolute_url
                )

    return links


def scan_public_resource(
    session,
    url,
    base_url,
):
    result = {
        "url": url,
        "status": "NOT CHECKED",
        "findings": [],
        "error": None,
    }

    if not is_same_host(
        base_url,
        url,
    ):
        result["status"] = "SKIPPED"
        return result

    try:
        response = session.get(
            url,
            timeout=8,
            allow_redirects=True,
        )

        if response.status_code >= 400:
            result["status"] = (
                f"HTTP {response.status_code}"
            )
            return result

        content_type = response.headers.get(
            "Content-Type",
            "",
        ).lower()

        if (
            "text" not in content_type
            and "json" not in content_type
            and "xml" not in content_type
        ):
            result["status"] = "SKIPPED"
            return result

        findings = scan_text_for_exposure(
            response.text
        )

        result["findings"] = findings
        result["status"] = "CHECKED"

        return result

    except requests.RequestException as error:
        result["status"] = "ERROR"
        result["error"] = str(error)

        return result


def scan_exposure(target):
    result = {
        "target": str(target),
        "base_url": None,
        "status": "NOT STARTED",
        "resources_checked": [],
        "findings": [],
        "error": None,
    }

    if not target:
        result["status"] = "INVALID TARGET"
        result["error"] = "Target is empty."
        return result

    base_url = normalize_base_url(target)

    result["base_url"] = base_url

    session = create_session()

    resources = []

    # Main page
    resources.append(base_url)

    # Common public resources
    for path in PUBLIC_FILES:
        resources.append(
            urljoin(
                base_url + "/",
                path.lstrip("/"),
            )
        )

    try:
        main_response = session.get(
            base_url,
            timeout=10,
            allow_redirects=True,
        )

        if main_response.status_code < 400:
            resources.extend(
                extract_public_document_links(
                    main_response,
                    base_url,
                )
            )

            main_findings = (
                scan_text_for_exposure(
                    main_response.text
                )
            )

            if main_findings:
                result["findings"].append({
                    "url": main_response.url,
                    "findings": main_findings,
                })

        # Deduplicate resources.
        unique_resources = []

        for resource in resources:
            if resource not in unique_resources:
                unique_resources.append(
                    resource
                )

        # Limit to avoid aggressive crawling.
        unique_resources = unique_resources[:30]

        for resource in unique_resources:
            if resource == base_url:
                continue

            checked = scan_public_resource(
                session,
                resource,
                base_url,
            )

            result[
                "resources_checked"
            ].append(checked)

            if checked.get("findings"):
                result["findings"].append({
                    "url": checked["url"],
                    "findings": checked[
                        "findings"
                    ],
                })

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


def count_resources(scan_result):
    return len(
        scan_result.get(
            "resources_checked",
            [],
        )
    )


def count_findings(scan_result):
    total = 0

    for item in scan_result.get(
        "findings",
        [],
    ):
        total += len(
            item.get(
                "findings",
                [],
            )
        )

    return total
