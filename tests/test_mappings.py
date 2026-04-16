"""Unit tests for etl/mappings.py — centralised protocol, attack, and service lookups."""

import sys
import os

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'etl'))

from mappings import (
    PROTOCOL_MAP, TRANSPORT_LAYER_MAP, LABEL_NORMALISATION,
    ATTACK_CATEGORY_MAP, SEVERITY_MAP, SERVICE_MAP, VALID_SEVERITIES,
    get_protocol_name, get_transport_layer, get_service,
    get_severity, get_label_severity, categorize_label, time_of_day,
    classify_ip, DAY_NAMES,
)


class TestProtocolMap:
    def test_tcp(self):
        assert PROTOCOL_MAP[6] == 'TCP'

    def test_udp(self):
        assert PROTOCOL_MAP[17] == 'UDP'

    def test_icmp(self):
        assert PROTOCOL_MAP[1] == 'ICMP'

    def test_get_protocol_name_known(self):
        assert get_protocol_name(6) == 'TCP'

    def test_get_protocol_name_unknown(self):
        assert get_protocol_name(999) == 'OTHER'


class TestTransportLayer:
    def test_tcp_is_transport(self):
        assert get_transport_layer('TCP') == 'Transport'

    def test_icmp_is_network(self):
        assert get_transport_layer('ICMP') == 'Network'

    def test_unknown_protocol(self):
        assert get_transport_layer('NONEXISTENT') == 'Unknown'

    def test_all_protocol_map_values_covered(self):
        for name in PROTOCOL_MAP.values():
            assert name in TRANSPORT_LAYER_MAP


class TestLabelNormalisation:
    def test_en_dash_brute_force(self):
        assert LABEL_NORMALISATION.get('Web Attack \u2013 Brute Force') == 'Web Attack -- Brute Force'

    def test_em_dash_xss(self):
        assert LABEL_NORMALISATION.get('Web Attack \u2014 XSS') == 'Web Attack -- XSS'

    def test_hyphen_sql_injection(self):
        assert LABEL_NORMALISATION.get('Web Attack - Sql Injection') == 'Web Attack -- Sql Injection'


class TestCategorizeLabel:
    @pytest.mark.parametrize("label,expected", [
        ('BENIGN', 'Normal'),
        ('benign', 'Normal'),
        ('DoS Hulk', 'DoS'),
        ('DoS GoldenEye', 'DoS'),
        ('DoS slowloris', 'DoS'),
        ('DoS Slowhttptest', 'DoS'),
        ('DDoS', 'DDoS'),
        ('PortScan', 'Reconnaissance'),
        ('FTP-Patator', 'Brute Force'),
        ('SSH-Patator', 'Brute Force'),
        ('Bot', 'Botnet'),
        ('Web Attack -- Brute Force', 'Web Attack'),
        ('Web Attack -- XSS', 'Web Attack'),
        ('Web Attack -- Sql Injection', 'Web Attack'),
        ('Infiltration', 'Infiltration'),
        ('Heartbleed', 'Exploitation'),
    ])
    def test_known_labels(self, label, expected):
        assert categorize_label(label) == expected

    def test_attempted_suffix_stripped(self):
        assert categorize_label('DoS Hulk - Attempted') == 'DoS'

    def test_prefix_fallback_dos(self):
        assert categorize_label('DoS SomeNewVariant') == 'DoS'

    def test_prefix_fallback_ddos(self):
        assert categorize_label('DDoS LOIT') == 'DDoS'

    def test_prefix_fallback_web_attack(self):
        assert categorize_label('Web Attack - Something') == 'Web Attack'

    def test_unknown_returns_unknown(self):
        assert categorize_label('CompletelyNewAttack') == 'Unknown'


class TestSeverityMap:
    def test_all_categories_have_severity(self):
        for cat in set(ATTACK_CATEGORY_MAP.values()):
            assert cat in SEVERITY_MAP

    def test_valid_severities_set(self):
        assert VALID_SEVERITIES == frozenset({'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'})

    def test_get_severity_known(self):
        assert get_severity('DoS') == 'HIGH'
        assert get_severity('Normal') == 'LOW'
        assert get_severity('DDoS') == 'CRITICAL'

    def test_get_severity_unknown(self):
        assert get_severity('NonexistentCategory') == 'LOW'


class TestServiceMap:
    def test_http(self):
        assert get_service(80) == ('HTTP', 'Web')

    def test_ssh(self):
        assert get_service(22) == ('SSH', 'Remote')

    def test_unknown_port(self):
        assert get_service(99999) == ('Unknown', 'Unknown')

    def test_https(self):
        assert get_service(443) == ('HTTPS', 'Web')

    def test_mysql(self):
        assert get_service(3306) == ('MySQL', 'Database')


class TestTimeOfDay:
    def test_morning(self):
        assert time_of_day(8) == 'Morning'
        assert time_of_day(11) == 'Morning'

    def test_afternoon(self):
        assert time_of_day(12) == 'Afternoon'
        assert time_of_day(17) == 'Afternoon'

    def test_evening(self):
        assert time_of_day(18) == 'Evening'
        assert time_of_day(22) == 'Evening'

    def test_night(self):
        assert time_of_day(23) == 'Night'
        assert time_of_day(0) == 'Night'
        assert time_of_day(5) == 'Night'


class TestClassifyIp:
    def test_class_a(self):
        assert classify_ip('10.0.0.1') == 'A'
        assert classify_ip('127.0.0.1') == 'A'

    def test_class_b(self):
        assert classify_ip('128.0.0.1') == 'B'
        assert classify_ip('191.255.0.1') == 'B'

    def test_class_c(self):
        assert classify_ip('192.168.1.1') == 'C'
        assert classify_ip('223.255.255.1') == 'C'

    def test_class_d(self):
        assert classify_ip('224.0.0.1') == 'D'

    def test_class_e(self):
        assert classify_ip('240.0.0.1') == 'E'

    def test_invalid_ip(self):
        assert classify_ip('not_an_ip') == 'Unknown'

    def test_empty_string(self):
        assert classify_ip('') == 'Unknown'


class TestGetLabelSeverity:
    def test_slowloris_is_medium(self):
        assert get_label_severity('DoS slowloris', 'DoS') == 'MEDIUM'

    def test_slowloris_case_insensitive(self):
        assert get_label_severity('DoS Slowloris', 'DoS') == 'MEDIUM'

    def test_hulk_uses_category_fallback(self):
        assert get_label_severity('DoS Hulk', 'DoS') == 'HIGH'

    def test_sql_injection_is_high(self):
        assert get_label_severity('Web Attack -- Sql Injection', 'Web Attack') == 'HIGH'

    def test_xss_is_medium(self):
        assert get_label_severity('Web Attack -- XSS', 'Web Attack') == 'MEDIUM'

    def test_unknown_label_uses_category(self):
        assert get_label_severity('SomethingNew', 'DDoS') == 'CRITICAL'

    def test_unknown_category_defaults_low(self):
        assert get_label_severity('Unknown', 'Unknown') == 'LOW'


class TestDayNames:
    def test_length(self):
        assert len(DAY_NAMES) == 7

    def test_monday_is_index_zero(self):
        assert DAY_NAMES[0] == 'Monday'

    def test_sunday_is_index_six(self):
        assert DAY_NAMES[6] == 'Sunday'
