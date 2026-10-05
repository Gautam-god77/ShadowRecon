import dns.resolver
import dns.exception


DEFAULT_WORDLIST = "wordlists/subdomains.txt"


def load_wordlist(path=DEFAULT_WORDLIST):
    """
    Load subdomain prefixes from a wordlist.
    """

    try:
        with open(path, "r", encoding="utf-8") as file:

            words = []

            for line in file:

                word = line.strip().lower()

                if not word:
                    continue

                if word.startswith("#"):
                    continue

                words.append(word)

            return words

    except FileNotFoundError:

        return []


def resolve_subdomain(hostname):
    """
    Resolve a hostname.

    Returns:
        list of resolved IP addresses
    """

    addresses = []

    for record_type in ("A", "AAAA"):

        try:

            answers = dns.resolver.resolve(
                hostname,
                record_type,
                lifetime=3,
            )

            for answer in answers:

                address = str(answer)

                if address not in addresses:
                    addresses.append(address)

        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            pass

        except Exception:
            pass

    return addresses


def discover_subdomains(
    domain,
    wordlist_path=DEFAULT_WORDLIST,
    callback=None,
):
    """
    Discover subdomains using DNS resolution.

    callback:
        Optional function used to report progress.

    Returns:
        List of dictionaries.
    """

    words = load_wordlist(wordlist_path)

    results = []

    total = len(words)

    if total == 0:
        return results

    for index, word in enumerate(words, start=1):

        hostname = f"{word}.{domain}"

        if callback:

            callback(
                index,
                total,
                hostname,
                "CHECKING",
                None,
            )

        addresses = resolve_subdomain(
            hostname
        )

        if addresses:

            result = {
                "hostname": hostname,
                "addresses": addresses,
                "status": "RESOLVED",
            }

            results.append(result)

            if callback:

                callback(
                    index,
                    total,
                    hostname,
                    "RESOLVED",
                    addresses,
                )

        else:

            if callback:

                callback(
                    index,
                    total,
                    hostname,
                    "NOT FOUND",
                    None,
                )

    return results
