import hashlib
import math
from collections import Counter

import magic


def shannon_entropy(data):
    taille = len(data)
    if taille == 0:
        return 0.0
    total = 0
    for count in Counter(data).values():
        p = count / taille
        total += -p * math.log2(p)
    return round(abs(total), 2)


def get_file_metadata(data):
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "size": len(data),
        "file_type": magic.from_buffer(data),
        "entropy": shannon_entropy(data),
    }
