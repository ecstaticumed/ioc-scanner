import ipaddress
import re


MD5_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_PATTERN = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")

DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)


def normalize_ioc(value):
    """Remove whitespace and normalize case."""

    return value.strip().lower()


def is_ip(value):
    """Check whether the value is a valid IPv4 or IPv6 address."""

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_url(value):
    """Basic URL identification."""

    return value.startswith(("http://", "https://"))


def is_domain(value):
    """Check whether the value resembles a domain."""

    return bool(DOMAIN_PATTERN.match(value))


def is_hash(value):
    """Identify MD5, SHA1, or SHA256 hashes."""

    if MD5_PATTERN.fullmatch(value):
        return "md5"

    if SHA1_PATTERN.fullmatch(value):
        return "sha1"

    if SHA256_PATTERN.fullmatch(value):
        return "sha256"

    return None


def classify_ioc(value):
    """Identify the type of IOC."""

    value = normalize_ioc(value)

    if is_ip(value):
        return "ip"

    if is_url(value):
        return "url"

    hash_type = is_hash(value)

    if hash_type:
        return hash_type

    if is_domain(value):
        return "domain"

    return "unknown"
