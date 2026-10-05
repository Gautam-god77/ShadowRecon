from dataclasses import dataclass
from urllib.parse import urlparse

from shadowrecon.utils.validators import (
    detect_target_type,
    normalize_url,
)


@dataclass
class Target:

    original: str
    target_type: str
    host: str
    url: str | None = None

    @classmethod
    def create(cls, value):

        value = value.strip()

        target_type = detect_target_type(value)

        if target_type == "DOMAIN":
            host = value.lower()
            url = normalize_url(value)

        elif target_type == "IP":
            host = value
            url = None

        else:
            url = normalize_url(value)
            host = urlparse(url).hostname.lower()

        return cls(
            original=value,
            target_type=target_type,
            host=host,
            url=url,
        )
