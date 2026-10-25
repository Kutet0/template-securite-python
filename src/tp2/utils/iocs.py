import re
import lief
import ipaddress

lief.logging.disable()

REGEX_URL = re.compile(r"https?://[^\s\"'<>]+")
REGEX_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
REGEX_DOMAIN = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-z]{2,}\b")
REGEX_MUTEX = re.compile(r"(?:Global|Local)\\[^\s\"']+")
REGEX_REGISTRY = re.compile(r"\b(?:HKLM|HKCU|HKEY_[A-Z_]+)\\[^\s\"']+")
REGEX_FLAG = re.compile(r"FLAG=(ESGI\{[^}]+\})")
FILE_EXTENSIONS = {"dll", "exe", "php", "sys", "txt", "bin"}


def extract_strings(data: bytes) -> list[str]:
    """
    Extrait les chaînes lisibles (ASCII et UTF-16) d'un contenu binaire.
    :param data:
    :return:
    """
    ascii = re.findall(rb"[\x20-\x7e]{4,}", data)
    ascii_string = [s.decode("ascii") for s in ascii]
    large = re.findall(rb"(?:[\x20-\x7e]\x00){4,}", data)
    large_string = [s.decode("utf-16-le") for s in large]
    return ascii_string + large_string


def get_payload(path: str, data: bytes) -> bytes:
    binary = lief.parse(path)
    if binary is not None and binary.has_overlay:
        return bytes(binary.overlay)
    return data


def extract_iocs(data: bytes) -> dict:
    text = "\n".join(extract_strings(data))

    urls = REGEX_URL.findall(text)
    mutexes = REGEX_MUTEX.findall(text)
    registry = REGEX_REGISTRY.findall(text)

    ips = [ip for ip in REGEX_IP.findall(text) if is_valid_ip(ip)]

    domains = [d for d in REGEX_DOMAIN.findall(text) if d.rsplit(".", 1)[-1].lower() not in FILE_EXTENSIONS]

    return {
        "domains": sorted(set(domains)),
        "ips": sorted(set(ips)),
        "urls": sorted(set(urls)),
        "mutex": sorted(set(mutexes)),
        "registry": sorted(set(registry)),
    }


def find_flag(data: bytes) -> list[str]:
    text = "\n".join(extract_strings(data))
    trouvés = REGEX_FLAG.findall(text)
    if trouvés:
        return trouvés[0]
    else:
        return ""


def is_valid_ip(ip: str) -> bool:
    """
    Vérifie qu'une chaîne est une adresse IP valide.
    :param ip:
    :return:
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
