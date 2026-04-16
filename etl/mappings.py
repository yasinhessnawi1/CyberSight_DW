"""
CyberSight DW — Centralized Mappings
Single source of truth for all protocol, attack, severity, service, and
transport-layer mappings used across the ETL pipeline and dashboard.
"""

# ---------------------------------------------------------------------------
# Protocol: IANA number -> human-readable name
# Covers all values observed in CICIDS 2017 plus common extras.
# ---------------------------------------------------------------------------
PROTOCOL_MAP: dict[int, str] = {
    0:   'HOPOPT',
    1:   'ICMP',
    2:   'IGMP',
    6:   'TCP',
    17:  'UDP',
    41:  'IPv6',
    43:  'IPv6-Route',
    44:  'IPv6-Frag',
    47:  'GRE',
    50:  'ESP',
    51:  'AH',
    58:  'ICMPv6',
    59:  'IPv6-NoNxt',
    60:  'IPv6-Opts',
    89:  'OSPF',
    103: 'PIM',
    112: 'VRRP',
    132: 'SCTP',
}

# ---------------------------------------------------------------------------
# Transport layer classification
# ---------------------------------------------------------------------------
TRANSPORT_LAYER_MAP: dict[str, str] = {
    'TCP':        'Transport',
    'UDP':        'Transport',
    'SCTP':       'Transport',
    'ICMP':       'Network',
    'ICMPv6':     'Network',
    'IGMP':       'Network',
    'HOPOPT':     'Network',
    'IPv6':       'Network',
    'IPv6-Route': 'Network',
    'IPv6-Frag':  'Network',
    'IPv6-NoNxt': 'Network',
    'IPv6-Opts':  'Network',
    'GRE':        'Network',
    'ESP':        'Network',
    'AH':         'Network',
    'OSPF':       'Network',
    'PIM':        'Network',
    'VRRP':       'Network',
    'OTHER':      'Unknown',
}

# ---------------------------------------------------------------------------
# Label normalisation: CICIDS 2017 uses inconsistent dash characters
# for web-attack labels.  Map all known variants to a canonical form.
# ---------------------------------------------------------------------------
LABEL_NORMALISATION: dict[str, str] = {
    # Brute Force
    'Web Attack \u2013 Brute Force':          'Web Attack -- Brute Force',
    'Web Attack \u2014 Brute Force':          'Web Attack -- Brute Force',
    'Web Attack \u00e2\u0080\u0093 Brute Force': 'Web Attack -- Brute Force',
    'Web Attack - Brute Force':               'Web Attack -- Brute Force',
    # XSS
    'Web Attack \u2013 XSS':                  'Web Attack -- XSS',
    'Web Attack \u2014 XSS':                  'Web Attack -- XSS',
    'Web Attack \u00e2\u0080\u0093 XSS':      'Web Attack -- XSS',
    'Web Attack - XSS':                       'Web Attack -- XSS',
    # SQL Injection
    'Web Attack \u2013 Sql Injection':        'Web Attack -- Sql Injection',
    'Web Attack \u2014 Sql Injection':        'Web Attack -- Sql Injection',
    'Web Attack \u00e2\u0080\u0093 Sql Injection': 'Web Attack -- Sql Injection',
    'Web Attack - Sql Injection':             'Web Attack -- Sql Injection',
}

# ---------------------------------------------------------------------------
# Attack category: lowercased label -> category.
# Used after label normalisation; keys MUST be lowercase.
# ---------------------------------------------------------------------------
ATTACK_CATEGORY_MAP: dict[str, str] = {
    'benign':                           'Normal',
    # DoS family
    'dos hulk':                         'DoS',
    'dos goldeneye':                    'DoS',
    'dos slowloris':                    'DoS',
    'dos slowhttptest':                 'DoS',
    # DDoS
    'ddos':                             'DDoS',
    'ddos loit':                        'DDoS',
    # Reconnaissance
    'portscan':                         'Reconnaissance',
    'port scan':                        'Reconnaissance',
    # Brute force
    'ftp-patator':                      'Brute Force',
    'ssh-patator':                      'Brute Force',
    # Botnet
    'bot':                              'Botnet',
    'botnet':                           'Botnet',
    # Web attacks (canonical form after normalisation)
    'web attack -- brute force':        'Web Attack',
    'web attack -- xss':                'Web Attack',
    'web attack -- sql injection':      'Web Attack',
    'web attack - brute force':         'Web Attack',
    'web attack - xss':                 'Web Attack',
    'web attack - sql injection':       'Web Attack',
    # Infiltration
    'infiltration':                     'Infiltration',
    'infiltration - portscan':          'Infiltration',
    'infiltration - cooldisc':          'Infiltration',
    'infiltration - dropbox':           'Infiltration',
    # Exploitation
    'heartbleed':                       'Exploitation',
}

# ---------------------------------------------------------------------------
# Severity per *category* (not per label)
# ---------------------------------------------------------------------------
SEVERITY_MAP: dict[str, str] = {
    'Normal':         'LOW',
    'DoS':            'HIGH',
    'DDoS':           'CRITICAL',
    'Reconnaissance': 'LOW',
    'Brute Force':    'MEDIUM',
    'Botnet':         'HIGH',
    'Web Attack':     'MEDIUM',
    'Infiltration':   'CRITICAL',
    'Exploitation':   'CRITICAL',
    'Unknown':        'LOW',
}

# Per-label severity overrides (more nuanced than category-level).
# Labels not listed here fall back to SEVERITY_MAP[category].
LABEL_SEVERITY_OVERRIDES: dict[str, str] = {
    'dos slowloris':                    'MEDIUM',
    'dos slowloris - attempted':        'MEDIUM',
    'dos slowhttptest':                 'MEDIUM',
    'dos slowhttptest - attempted':     'MEDIUM',
    'web attack -- sql injection':      'HIGH',
    'web attack -- brute force':        'MEDIUM',
    'web attack -- xss':                'MEDIUM',
}

VALID_SEVERITIES = frozenset(SEVERITY_MAP.values())

# ---------------------------------------------------------------------------
# Service: destination port -> (service_name, service_type)
# ---------------------------------------------------------------------------
SERVICE_MAP: dict[int, tuple[str, str]] = {
    20:    ('FTP-Data', 'File Transfer'),
    21:    ('FTP', 'File Transfer'),
    22:    ('SSH', 'Remote'),
    23:    ('Telnet', 'Remote'),
    25:    ('SMTP', 'Email'),
    53:    ('DNS', 'Network'),
    67:    ('DHCP', 'Network'),
    68:    ('DHCP', 'Network'),
    69:    ('TFTP', 'File Transfer'),
    80:    ('HTTP', 'Web'),
    110:   ('POP3', 'Email'),
    111:   ('RPC', 'Network'),
    123:   ('NTP', 'Network'),
    135:   ('MSRPC', 'Remote'),
    137:   ('NetBIOS', 'Network'),
    138:   ('NetBIOS', 'Network'),
    139:   ('NetBIOS', 'Network'),
    143:   ('IMAP', 'Email'),
    161:   ('SNMP', 'Network'),
    162:   ('SNMP-Trap', 'Network'),
    389:   ('LDAP', 'Directory'),
    443:   ('HTTPS', 'Web'),
    445:   ('SMB', 'File Transfer'),
    465:   ('SMTPS', 'Email'),
    514:   ('Syslog', 'Logging'),
    587:   ('SMTP-Sub', 'Email'),
    636:   ('LDAPS', 'Directory'),
    993:   ('IMAPS', 'Email'),
    995:   ('POP3S', 'Email'),
    1433:  ('MSSQL', 'Database'),
    1521:  ('Oracle', 'Database'),
    3306:  ('MySQL', 'Database'),
    3389:  ('RDP', 'Remote'),
    5432:  ('PostgreSQL', 'Database'),
    5900:  ('VNC', 'Remote'),
    6379:  ('Redis', 'Database'),
    8080:  ('HTTP-Alt', 'Web'),
    8443:  ('HTTPS-Alt', 'Web'),
    8888:  ('HTTP-Proxy', 'Web'),
    11211: ('Memcached', 'Database'),
    27017: ('MongoDB', 'Database'),
}

# ---------------------------------------------------------------------------
# Day names (Monday-index-0)
# ---------------------------------------------------------------------------
DAY_NAMES = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_protocol_name(number: int) -> str:
    """Resolve a protocol number to its name, falling back to 'OTHER'."""
    return PROTOCOL_MAP.get(number, 'OTHER')


def get_transport_layer(protocol_name: str) -> str:
    """Return the transport layer for a protocol name."""
    return TRANSPORT_LAYER_MAP.get(protocol_name, 'Unknown')


def get_service(port: int) -> tuple[str, str]:
    """Return (service_name, service_type) for a destination port."""
    return SERVICE_MAP.get(port, ('Unknown', 'Unknown'))


def get_severity(category: str) -> str:
    """Return the severity for a given attack category."""
    return SEVERITY_MAP.get(category, 'LOW')


def get_label_severity(label: str, category: str) -> str:
    """Return severity for a label, using per-label overrides when available."""
    override = LABEL_SEVERITY_OVERRIDES.get(label.lower().strip())
    if override:
        return override
    return SEVERITY_MAP.get(category, 'LOW')


def categorize_label(label: str) -> str:
    """Map an attack label to its category using case-insensitive lookup
    with prefix-based fallback."""
    key = label.lower().strip()
    if key in ATTACK_CATEGORY_MAP:
        return ATTACK_CATEGORY_MAP[key]
    base = key.replace(' - attempted', '').strip()
    if base in ATTACK_CATEGORY_MAP:
        return ATTACK_CATEGORY_MAP[base]
    if base.startswith('dos '):
        return 'DoS'
    if base.startswith('ddos'):
        return 'DDoS'
    if base.startswith('web attack'):
        return 'Web Attack'
    if base.startswith('infiltration'):
        return 'Infiltration'
    if base.startswith('botnet') or base == 'bot':
        return 'Botnet'
    if base.startswith('portscan') or base.startswith('port scan'):
        return 'Reconnaissance'
    return 'Unknown'


def time_of_day(hour: int) -> str:
    """Bucket an hour (0-23) into a time-of-day label."""
    if 6 <= hour <= 11:
        return 'Morning'
    if 12 <= hour <= 17:
        return 'Afternoon'
    if 18 <= hour <= 22:
        return 'Evening'
    return 'Night'


def classify_ip(ip_str: str) -> str:
    """Classify an IPv4 address by its class (A/B/C/D/E)."""
    try:
        first_octet = int(ip_str.split('.')[0])
    except (ValueError, IndexError):
        return 'Unknown'
    if first_octet < 128:
        return 'A'
    if first_octet < 192:
        return 'B'
    if first_octet < 224:
        return 'C'
    if first_octet < 240:
        return 'D'
    return 'E'
