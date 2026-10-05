import time

import requests
from bs4 import BeautifulSoup


USER_AGENT = (
    "ShadowRecon/1.0 "
    "(Authorized Security Reconnaissance)"
)


def scan_http(target):
    """
    Perform basic HTTP/HTTPS reconnaissance.

    Returns a dictionary containing:
        - reachable
        - status_code
        - title
        - final_url
        - server
        - content_type
        - content_length
        - response_time
        - redirects
    """

    urls = []

    if target.url:
        urls.append(target.url)

    else:
        urls.append(
            f"https://{target.host}"
        )

        urls.append(
            f"http://{target.host}"
        )

    result = {
        "reachable": False,
        "status_code": None,
        "title": None,
        "final_url": None,
        "server": None,
        "content_type": None,
        "content_length": None,
        "response_time": None,
        "redirects": [],
        "scheme": None,
        "error": None,
    }

    session = requests.Session()

    session.headers.update({
        "User-Agent": USER_AGENT
    })

    for url in urls:

        try:

            start = time.perf_counter()

            response = session.get(
                url,
                timeout=8,
                allow_redirects=True,
            )

            end = time.perf_counter()

            response_time = round(
                (end - start) * 1000,
                2,
            )

            result["reachable"] = True

            result["status_code"] = (
                response.status_code
            )

            result["final_url"] = (
                response.url
            )

            result["scheme"] = (
                response.url.split(":", 1)[0]
            )

            result["server"] = (
                response.headers.get(
                    "Server",
                    "N/A"
                )
            )

            result["content_type"] = (
                response.headers.get(
                    "Content-Type",
                    "N/A"
                )
            )

            result["content_length"] = (
                response.headers.get(
                    "Content-Length",
                    "N/A"
                )
            )

            result["response_time"] = (
                response_time
            )

            result["redirects"] = [
                {
                    "status": item.status_code,
                    "url": item.url,
                    "location": item.headers.get(
                        "Location",
                        ""
                    ),
                }
                for item in response.history
            ]

            # --------------------------------------------
            # PAGE TITLE
            # --------------------------------------------

            try:

                content_type = response.headers.get(
                    "Content-Type",
                    ""
                ).lower()

                if "text/html" in content_type:

                    soup = BeautifulSoup(
                        response.text,
                        "html.parser",
                    )

                    if soup.title:

                        result["title"] = (
                            soup.title.get_text(
                                strip=True
                            )
                        )

                    else:

                        result["title"] = "N/A"

                else:

                    result["title"] = "N/A"

            except Exception:

                result["title"] = "N/A"

            return result

        except requests.RequestException as error:

            result["error"] = str(error)

    return result
