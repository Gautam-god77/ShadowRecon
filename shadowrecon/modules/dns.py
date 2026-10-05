import dns.resolver
import dns.exception


RECORD_TYPES = [
    "A",
    "AAAA",
    "MX",
    "NS",
    "CNAME",
    "TXT",
    "SOA",
]


def query_record(domain, record_type):
    """
    Query a single DNS record type.

    Returns a list of strings.
    """

    results = []

    try:
        answers = dns.resolver.resolve(
            domain,
            record_type,
            lifetime=5,
        )

        for answer in answers:
            results.append(str(answer))

    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        pass

    except Exception:
        pass

    return results


def scan_dns(domain):
    """
    Perform DNS reconnaissance for the supplied domain.

    Returns a dictionary containing discovered records.
    """

    results = {}

    for record_type in RECORD_TYPES:

        records = query_record(
            domain,
            record_type,
        )

        results[record_type] = records

    return results
