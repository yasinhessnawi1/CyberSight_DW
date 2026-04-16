"""Unit tests for etl/producer.py — row transformation and column naming."""

import sys
import os
from collections import namedtuple
from datetime import datetime

import pandas as pd
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'etl'))

from producer import row_to_message, safe_col_name


class TestSafeColName:
    def test_spaces_replaced(self):
        assert safe_col_name('Source IP') == 'Source_IP'

    def test_slashes_replaced(self):
        assert safe_col_name('Flow Bytes/s') == 'Flow_Bytes_s'

    def test_parens_removed(self):
        assert safe_col_name('Fwd (IAT)') == 'Fwd_IAT'

    def test_multiple_spaces(self):
        assert safe_col_name('Total Length of Fwd Packets') == 'Total_Length_of_Fwd_Packets'

    def test_already_safe(self):
        assert safe_col_name('protocol') == 'protocol'


class TestRowToMessage:
    def _make_row(self, **overrides):
        fields = {
            'Timestamp': pd.Timestamp('2017-07-05T10:00:00'),
            'Source_IP': '192.168.1.1',
            'Source_Port': 12345,
            'Destination_IP': '10.0.0.1',
            'Destination_Port': 80,
            'Protocol': 'TCP',
            'Flow_Duration': 5000,
            'Total_Fwd_Packets': 10,
            'Total_Backward_Packets': 5,
            'Total_Length_of_Fwd_Packets': 2048,
            'Total_Length_of_Bwd_Packets': 512,
            'Flow_Bytes_s': 100.5,
            'Flow_Packets_s': 10.0,
            'Label': 'BENIGN',
            'attack_category': 'Normal',
            'severity': 'LOW',
            'source_country': 'China',
            'source_region': 'Asia',
        }
        fields.update(overrides)
        Row = namedtuple('Row', fields.keys())
        return Row(**fields)

    def test_returns_dict(self):
        row = self._make_row()
        msg = row_to_message(row)
        assert isinstance(msg, dict)

    def test_timestamp_is_iso_string(self):
        row = self._make_row()
        msg = row_to_message(row)
        assert '2017-07-05' in msg['timestamp']

    def test_source_fields(self):
        row = self._make_row()
        msg = row_to_message(row)
        assert msg['source_ip'] == '192.168.1.1'
        assert msg['source_port'] == 12345

    def test_destination_fields(self):
        row = self._make_row()
        msg = row_to_message(row)
        assert msg['destination_ip'] == '10.0.0.1'
        assert msg['destination_port'] == 80

    def test_label_field(self):
        row = self._make_row(Label='DoS Hulk')
        msg = row_to_message(row)
        assert msg['label'] == 'DoS Hulk'

    def test_attack_category_field(self):
        row = self._make_row(attack_category='DoS')
        msg = row_to_message(row)
        assert msg['attack_category'] == 'DoS'

    def test_numeric_fields_are_ints(self):
        row = self._make_row()
        msg = row_to_message(row)
        assert isinstance(msg['flow_duration'], int)
        assert isinstance(msg['fwd_packets'], int)
        assert isinstance(msg['bwd_packets'], int)
        assert isinstance(msg['fwd_bytes'], int)
        assert isinstance(msg['bwd_bytes'], int)

    def test_rate_fields_are_floats(self):
        row = self._make_row()
        msg = row_to_message(row)
        assert isinstance(msg['flow_bytes_per_sec'], float)
        assert isinstance(msg['flow_packets_per_sec'], float)

    def test_geo_fields(self):
        row = self._make_row()
        msg = row_to_message(row)
        assert msg['source_country'] == 'China'
        assert msg['source_region'] == 'Asia'

    def test_all_expected_keys_present(self):
        row = self._make_row()
        msg = row_to_message(row)
        expected_keys = {
            'source_ip', 'source_port', 'destination_ip', 'destination_port',
            'protocol', 'timestamp', 'flow_duration', 'fwd_packets',
            'bwd_packets', 'fwd_bytes', 'bwd_bytes', 'flow_bytes_per_sec',
            'flow_packets_per_sec', 'label', 'attack_category', 'severity',
            'source_country', 'source_region',
        }
        assert set(msg.keys()) == expected_keys
