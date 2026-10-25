import re


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
