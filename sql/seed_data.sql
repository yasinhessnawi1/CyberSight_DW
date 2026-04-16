-- ============================================================
-- CyberSight DW — Dimension Seed Data
-- Auto-executed on container first start via docker-entrypoint-initdb.d
-- ============================================================

-- Seed dim_protocol (extended to cover all IANA numbers in CICIDS 2017)
INSERT INTO dim_protocol (protocol_name, transport_layer) VALUES
    ('TCP',        'Transport'),
    ('UDP',        'Transport'),
    ('SCTP',       'Transport'),
    ('ICMP',       'Network'),
    ('ICMPv6',     'Network'),
    ('IGMP',       'Network'),
    ('HOPOPT',     'Network'),
    ('IPv6',       'Network'),
    ('IPv6-Route', 'Network'),
    ('IPv6-Frag',  'Network'),
    ('IPv6-NoNxt', 'Network'),
    ('IPv6-Opts',  'Network'),
    ('GRE',        'Network'),
    ('ESP',        'Network'),
    ('AH',         'Network'),
    ('OSPF',       'Network'),
    ('PIM',        'Network'),
    ('VRRP',       'Network'),
    ('OTHER',      'Unknown');

-- Seed dim_attack with all known CICIDS 2017 labels
INSERT INTO dim_attack (attack_label, attack_category, severity, description) VALUES
    ('BENIGN',                          'Normal',         'LOW',      'Normal network traffic'),
    ('DoS Hulk',                        'DoS',            'HIGH',     'HTTP GET flood using Hulk tool'),
    ('DoS GoldenEye',                   'DoS',            'HIGH',     'HTTP DoS using GoldenEye tool'),
    ('DoS slowloris',                   'DoS',            'MEDIUM',   'Slow HTTP header attack'),
    ('DoS Slowhttptest',                'DoS',            'MEDIUM',   'Slow HTTP body attack'),
    ('DDoS',                            'DDoS',           'CRITICAL', 'Distributed Denial of Service'),
    ('DDoS LOIT',                       'DDoS',           'CRITICAL', 'DDoS Low Orbit Ion Cannon'),
    ('PortScan',                        'Reconnaissance', 'LOW',      'Port scanning activity'),
    ('FTP-Patator',                     'Brute Force',    'MEDIUM',   'FTP credential brute force'),
    ('SSH-Patator',                     'Brute Force',    'MEDIUM',   'SSH credential brute force'),
    ('Bot',                             'Botnet',         'HIGH',     'Botnet activity'),
    ('Web Attack -- Brute Force',       'Web Attack',     'MEDIUM',   'Web form brute force'),
    ('Web Attack -- XSS',               'Web Attack',     'MEDIUM',   'Cross-site scripting attack'),
    ('Web Attack -- Sql Injection',     'Web Attack',     'HIGH',     'SQL injection attempt'),
    ('Infiltration',                    'Infiltration',   'CRITICAL', 'Network infiltration attempt'),
    ('Infiltration - Portscan',         'Infiltration',   'CRITICAL', 'Infiltration via port scanning'),
    ('Infiltration - CoolDisc',         'Infiltration',   'CRITICAL', 'Infiltration via CoolDisc'),
    ('Infiltration - Dropbox',          'Infiltration',   'CRITICAL', 'Infiltration via Dropbox download'),
    ('Heartbleed',                      'Exploitation',   'CRITICAL', 'OpenSSL Heartbleed exploit'),
    ('DoS Slowloris',                   'DoS',            'MEDIUM',   'Slow HTTP header attack (case variant)'),
    ('DoS Hulk - Attempted',            'DoS',            'HIGH',     'Attempted DoS Hulk attack'),
    ('DoS GoldenEye - Attempted',       'DoS',            'HIGH',     'Attempted DoS GoldenEye attack'),
    ('DoS Slowhttptest - Attempted',    'DoS',            'MEDIUM',   'Attempted slow HTTP body attack'),
    ('DoS Slowloris - Attempted',       'DoS',            'MEDIUM',   'Attempted slow HTTP header attack'),
    ('FTP-Patator - Attempted',         'Brute Force',    'MEDIUM',   'Attempted FTP brute force'),
    ('SSH-Patator - Attempted',         'Brute Force',    'MEDIUM',   'Attempted SSH brute force');
