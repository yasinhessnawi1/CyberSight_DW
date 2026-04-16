"""
CyberSight DW — Simulated IP-to-Country Mapping
Uses a deterministic hash of the IP string to assign a country from a
weighted distribution of known threat-actor regions.
Same IP always maps to the same country.
"""

import hashlib

COUNTRIES = [
    ('China',         'Asia',          18),
    ('Russia',        'Europe',        14),
    ('United States', 'North America', 12),
    ('Brazil',        'South America', 8),
    ('India',         'Asia',          8),
    ('Iran',          'Asia',          6),
    ('North Korea',   'Asia',          5),
    ('Germany',       'Europe',        5),
    ('Nigeria',       'Africa',        4),
    ('Vietnam',       'Asia',          4),
    ('Indonesia',     'Asia',          3),
    ('Turkey',        'Europe',        3),
    ('Ukraine',       'Europe',        3),
    ('Pakistan',      'Asia',          3),
    ('Romania',       'Europe',        2),
    ('Netherlands',   'Europe',        2),
]

_LOOKUP: list[tuple[str, str]] = []

for country, region, weight in COUNTRIES:
    _LOOKUP.extend([(country, region)] * weight)


def get_geo(ip: str) -> tuple[str, str]:
    """
    Return (country, region) for an IP address.
    Deterministic: same IP always returns the same result.
    """
    h = int(hashlib.md5(ip.encode()).hexdigest(), 16)
    idx = h % len(_LOOKUP)
    return _LOOKUP[idx]
