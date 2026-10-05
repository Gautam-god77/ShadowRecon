import re
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup


USER_AGENT = (
    "ShadowRecon/1.0 "
    "(Authorized Security Reconnaissance)"
)


def create_session():
    session = requests.Session()

    session.headers.update(
        {
            "User-Agent": USER_AGENT
        }
    )

    return session


def add_technology(
    technologies,
    name,
    category,
    evidence,
):
    """
    Add a technology only once.
    """

    for item in technologies:

        if (
            item["name"].lower()
            == name.lower()
        ):

            return

    technologies.append(
        {
            "name": name,
            "category": category,
            "evidence": evidence,
        }
    )


def detect_server_headers(
    response,
    technologies,
):
    """
    Detect technologies from HTTP headers.
    """

    server = response.headers.get(
        "Server",
        ""
    ).strip()

    powered_by = response.headers.get(
        "X-Powered-By",
        ""
    ).strip()

    if server:

        add_technology(
            technologies,
            server,
            "Web Server",
            f"Server: {server}",
        )

    if powered_by:

        add_technology(
            technologies,
            powered_by,
            "Backend",
            f"X-Powered-By: {powered_by}",
        )


def detect_generator(
    soup,
    technologies,
):
    """
    Detect CMS/platform generators from meta tags.
    """

    generator = soup.find(
        "meta",
        attrs={
            "name": re.compile(
                r"^generator$",
                re.I,
            )
        },
    )

    if not generator:

        return

    content = generator.get(
        "content",
        ""
    ).strip()

    if not content:

        return

    add_technology(
        technologies,
        content,
        "CMS / Generator",
        f"Meta generator: {content}",
    )


def detect_html_frameworks(
    html,
    soup,
    technologies,
):
    """
    Detect common publicly visible framework/CMS indicators.

    This is fingerprinting, not exploitation.
    """

    html_lower = html.lower()

    # WordPress
    if (
        "/wp-content/"
        in html_lower
        or "/wp-includes/"
        in html_lower
        or soup.find(
            "meta",
            attrs={
                "name": re.compile(
                    r"generator",
                    re.I,
                )
            },
        )
        and "wordpress"
        in str(soup).lower()
    ):

        add_technology(
            technologies,
            "WordPress",
            "CMS",
            "WordPress paths or metadata detected",
        )

    # Drupal
    if (
        "/sites/default/"
        in html_lower
        or "drupalsettings"
        in html_lower
        or "drupal"
        in html_lower
    ):

        add_technology(
            technologies,
            "Drupal",
            "CMS",
            "Drupal indicator detected",
        )

    # Joomla
    if (
        "/media/system/"
        in html_lower
        or "/media/jui/"
        in html_lower
    ):

        add_technology(
            technologies,
            "Joomla",
            "CMS",
            "Joomla path detected",
        )

    # Laravel
    if "laravel_session" in html_lower:

        add_technology(
            technologies,
            "Laravel",
            "Framework",
            "laravel_session cookie detected",
        )

    # React
    if (
        'data-reactroot'
        in html_lower
        or "__react"
        in html_lower
    ):

        add_technology(
            technologies,
            "React",
            "JavaScript Framework",
            "React DOM/runtime indicator detected",
        )

    # Angular
    if (
        "ng-version"
        in html_lower
        or "_nghost-"
        in html_lower
    ):

        add_technology(
            technologies,
            "Angular",
            "JavaScript Framework",
            "Angular DOM indicator detected",
        )

    # Vue
    if (
        "data-v-"
        in html_lower
        or "__vue__"
        in html_lower
    ):

        add_technology(
            technologies,
            "Vue.js",
            "JavaScript Framework",
            "Vue DOM/runtime indicator detected",
        )

    # Bootstrap
    if (
        "bootstrap"
        in html_lower
    ):

        add_technology(
            technologies,
            "Bootstrap",
            "CSS Framework",
            "Bootstrap reference detected",
        )

    # Tailwind
    if (
        "tailwind"
        in html_lower
    ):

        add_technology(
            technologies,
            "Tailwind CSS",
            "CSS Framework",
            "Tailwind reference detected",
        )


def detect_javascript(
    soup,
    technologies,
):
    """
    Inspect publicly referenced JavaScript files.
    """

    scripts = soup.find_all(
        "script"
    )

    for script in scripts:

        src = script.get(
            "src"
        )

        if not src:
            continue

        src_lower = src.lower()

        if "jquery" in src_lower:

            add_technology(
                technologies,
                "jQuery",
                "JavaScript Library",
                f"Script: {src}",
            )

        if "bootstrap" in src_lower:

            add_technology(
                technologies,
                "Bootstrap",
                "CSS/JS Framework",
                f"Script: {src}",
            )

        if "react" in src_lower:

            add_technology(
                technologies,
                "React",
                "JavaScript Framework",
                f"Script: {src}",
            )

        if "vue" in src_lower:

            add_technology(
                technologies,
                "Vue.js",
                "JavaScript Framework",
                f"Script: {src}",
            )

        if "angular" in src_lower:

            add_technology(
                technologies,
                "Angular",
                "JavaScript Framework",
                f"Script: {src}",
            )


def detect_cookies(
    response,
    technologies,
):
    """
    Detect technology-related cookie names.
    """

    cookies = response.cookies

    cookie_names = [
        cookie.name.lower()
        for cookie in cookies
    ]

    if any(
        "laravel_session" in name
        for name in cookie_names
    ):

        add_technology(
            technologies,
            "Laravel",
            "Framework",
            "laravel_session cookie",
        )

    if any(
        "wordpress" in name
        for name in cookie_names
    ):

        add_technology(
            technologies,
            "WordPress",
            "CMS",
            "WordPress-related cookie",
        )

    if any(
        "asp.net" in name
        for name in cookie_names
    ):

        add_technology(
            technologies,
            "ASP.NET",
            "Framework",
            "ASP.NET-related cookie",
        )


def scan_technology(
    target,
):
    """
    Perform passive/public technology fingerprinting
    against a web target.
    """

    result = {
        "target": target,
        "status": "NOT STARTED",
        "url": None,
        "technologies": [],
        "error": None,
    }

    if not target:

        result["status"] = "INVALID TARGET"

        result["error"] = (
            "Target is empty."
        )

        return result

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

        technologies = []

        detect_server_headers(
            response,
            technologies,
        )

        detect_cookies(
            response,
            technologies,
        )

        content_type = response.headers.get(
            "Content-Type",
            "",
        ).lower()

        if "text/html" in content_type:

            soup = BeautifulSoup(
                response.text,
                "html.parser",
            )

            detect_generator(
                soup,
                technologies,
            )

            detect_html_frameworks(
                response.text,
                soup,
                technologies,
            )

            detect_javascript(
                soup,
                technologies,
            )

        result["status"] = "COMPLETE"

        result["technologies"] = technologies

        return result

    except requests.RequestException as error:

        result["status"] = "ERROR"

        result["error"] = str(error)

        return result

    except Exception as error:

        result["status"] = "ERROR"

        result["error"] = str(error)

        return result
