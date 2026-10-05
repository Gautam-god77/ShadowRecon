import re
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


USER_AGENT = (
    "ShadowRecon/1.0 "
    "(Authorized Security Reconnaissance)"
)


EMAIL_REGEX = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b"
)

PHONE_REGEX = re.compile(
    r"(?<!\d)"
    r"(?:\+?\d{1,3}[\s.-]?)?"
    r"(?:\(?\d{2,4}\)?[\s.-]?)?"
    r"\d{3,4}[\s.-]?\d{3,4}"
    r"(?!\d)"
)


CONTACT_KEYWORDS = (
    "contact",
    "contact-us",
    "contactus",
    "about",
    "about-us",
    "support",
    "help",
    "customer-service",
    "reach-us",
)


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

        return base_host.lower() == target_host.lower()

    except Exception:
        return False


def normalize_email(email):
    return email.strip().lower()


def normalize_phone(phone):
    phone = phone.strip()

    phone = re.sub(
        r"\s+",
        " ",
        phone,
    )

    return phone


def is_valid_email(email):
    return bool(
        EMAIL_REGEX.fullmatch(email)
    )


def looks_like_contact_link(text, href):
    combined = (
        f"{text} {href}"
    ).lower()

    return any(
        keyword in combined
        for keyword in CONTACT_KEYWORDS
    )


def extract_emails(text):
    emails = set()

    for match in EMAIL_REGEX.findall(text):
        email = normalize_email(match)

        if is_valid_email(email):
            emails.add(email)

    return sorted(emails)


def extract_mailto_emails(soup):
    emails = set()

    for link in soup.find_all(
        "a",
        href=True,
    ):
        href = link.get("href", "").strip()

        if not href.lower().startswith("mailto:"):
            continue

        value = href[7:].split("?", 1)[0].strip()

        if is_valid_email(value):
            emails.add(
                normalize_email(value)
            )

    return sorted(emails)


def extract_phone_numbers(text):
    phones = set()

    for match in PHONE_REGEX.findall(text):
        phone = normalize_phone(match)

        digits = re.sub(
            r"\D",
            "",
            phone,
        )

        # Avoid treating very short numbers
        # as phone numbers.
        if len(digits) < 7:
            continue

        # Avoid extremely long random numeric strings.
        if len(digits) > 15:
            continue

        phones.add(phone)

    return sorted(phones)


def discover_contact_pages(
    soup,
    base_url,
):
    pages = []

    for link in soup.find_all(
        "a",
        href=True,
    ):
        href = link.get("href", "").strip()

        if not href:
            continue

        text = link.get_text(
            " ",
            strip=True,
        )

        if not looks_like_contact_link(
            text,
            href,
        ):
            continue

        if href.startswith((
            "#",
            "mailto:",
            "tel:",
            "javascript:",
        )):
            continue

        absolute_url = urljoin(
            base_url + "/",
            href,
        )

        if not is_same_host(
            base_url,
            absolute_url,
        ):
            continue

        parsed = urlparse(
            absolute_url
        )

        clean_url = parsed._replace(
            fragment=""
        ).geturl()

        if clean_url not in pages:
            pages.append(clean_url)

    return pages


def extract_public_contact_info(
    response,
    base_url,
):
    emails = set()
    phones = set()
    contact_pages = set()

    content_type = response.headers.get(
        "Content-Type",
        "",
    ).lower()

    if "text/html" not in content_type:
        return {
            "emails": [],
            "phones": [],
            "contact_pages": [],
        }

    try:
        soup = BeautifulSoup(
            response.text,
            "html.parser",
        )

    except Exception:
        return {
            "emails": [],
            "phones": [],
            "contact_pages": [],
        }

    # Extract from visible page text.
    visible_text = soup.get_text(
        " ",
        strip=True,
    )

    for email in extract_emails(
        visible_text
    ):
        emails.add(email)

    for phone in extract_phone_numbers(
        visible_text
    ):
        phones.add(phone)

    # Extract mailto links.
    for email in extract_mailto_emails(
        soup
    ):
        emails.add(email)

    # Discover contact-related pages.
    for page in discover_contact_pages(
        soup,
        base_url,
    ):
        contact_pages.add(page)

    return {
        "emails": sorted(emails),
        "phones": sorted(phones),
        "contact_pages": sorted(
            contact_pages
        ),
    }


def scan_contact_info(target):
    result = {
        "target": str(target),
        "base_url": None,
        "status": "NOT STARTED",
        "emails": [],
        "phones": [],
        "contact_pages": [],
        "pages_checked": [],
        "error": None,
    }

    if not target:
        result["status"] = "INVALID TARGET"
        result["error"] = "Target is empty."
        return result

    base_url = normalize_base_url(target)

    result["base_url"] = base_url

    session = create_session()

    pages_to_check = [
        base_url
    ]

    checked_pages = set()

    try:
        index_response = session.get(
            base_url,
            timeout=10,
            allow_redirects=True,
        )

        checked_pages.add(
            index_response.url
        )

        index_data = extract_public_contact_info(
            index_response,
            base_url,
        )

        pages_to_check.extend(
            index_data["contact_pages"]
        )

        for email in index_data["emails"]:
            if email not in result["emails"]:
                result["emails"].append(
                    email
                )

        for phone in index_data["phones"]:
            if phone not in result["phones"]:
                result["phones"].append(
                    phone
                )

        for page in index_data[
            "contact_pages"
        ]:
            if page not in result[
                "contact_pages"
            ]:
                result["contact_pages"].append(
                    page
                )

        # Check discovered contact pages.
        for page_url in pages_to_check[1:]:
            if page_url in checked_pages:
                continue

            try:
                response = session.get(
                    page_url,
                    timeout=8,
                    allow_redirects=True,
                )

                checked_pages.add(
                    response.url
                )

                page_data = (
                    extract_public_contact_info(
                        response,
                        base_url,
                    )
                )

                for email in page_data[
                    "emails"
                ]:
                    if email not in result[
                        "emails"
                    ]:
                        result[
                            "emails"
                        ].append(email)

                for phone in page_data[
                    "phones"
                ]:
                    if phone not in result[
                        "phones"
                    ]:
                        result[
                            "phones"
                        ].append(phone)

                for contact_page in page_data[
                    "contact_pages"
                ]:
                    if contact_page not in result[
                        "contact_pages"
                    ]:
                        result[
                            "contact_pages"
                        ].append(
                            contact_page
                        )

            except requests.RequestException:
                continue

        result["pages_checked"] = sorted(
            checked_pages
        )

        result["emails"] = sorted(
            set(result["emails"])
        )

        result["phones"] = sorted(
            set(result["phones"])
        )

        result["contact_pages"] = sorted(
            set(result["contact_pages"])
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


def count_emails(scan_result):
    return len(
        scan_result.get(
            "emails",
            [],
        )
    )


def count_phone_numbers(scan_result):
    return len(
        scan_result.get(
            "phones",
            [],
        )
    )


def count_contact_pages(scan_result):
    return len(
        scan_result.get(
            "contact_pages",
            [],
        )
    )
