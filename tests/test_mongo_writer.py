"""Unit tests for etl/mongo_writer.py — document transformation logic."""

import sys
import os
from datetime import datetime

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'etl'))

from mongo_writer import event_to_document


class TestEventToDocument:
    def _sample_event(self, **overrides):
        event = {
            'source_ip': '192.168.1.1',
            'source_port': 12345,
            'destination_ip': '10.0.0.1',
            'destination_port': 80,
            'protocol': 'TCP',
            'timestamp': '2017-07-05T10:30:00',
            'flow_duration': 5000,
            'fwd_packets': 10,
            'bwd_packets': 5,
            'fwd_bytes': 2048,
            'bwd_bytes': 512,
            'flow_bytes_per_sec': 100.5,
            'flow_packets_per_sec': 10.0,
            'label': 'DoS Hulk',
            'attack_category': 'DoS',
            'severity': 'HIGH',
            'source_country': 'China',
            'source_region': 'Asia',
        }
        event.update(overrides)
        return event

    def test_returns_dict(self):
        doc = event_to_document(self._sample_event())
        assert isinstance(doc, dict)

    def test_has_all_top_level_keys(self):
        doc = event_to_document(self._sample_event())
        expected_keys = {'timestamp', 'time', 'source', 'destination', 'attack', 'protocol', 'metrics'}
        assert expected_keys == set(doc.keys())

    def test_timestamp_is_datetime(self):
        doc = event_to_document(self._sample_event())
        assert isinstance(doc['timestamp'], datetime)

    def test_time_subdocument(self):
        doc = event_to_document(self._sample_event())
        t = doc['time']
        assert t['hour'] == 10
        assert t['day'] == 5
        assert t['month'] == 7
        assert t['year'] == 2017
        assert t['day_of_week'] == 'Wednesday'
        assert t['is_weekend'] is False
        assert t['time_of_day'] == 'Morning'

    def test_source_subdocument(self):
        doc = event_to_document(self._sample_event())
        s = doc['source']
        assert s['ip'] == '192.168.1.1'
        assert s['port'] == 12345
        assert s['country'] == 'China'
        assert s['region'] == 'Asia'

    def test_destination_subdocument(self):
        doc = event_to_document(self._sample_event())
        d = doc['destination']
        assert d['ip'] == '10.0.0.1'
        assert d['port'] == 80
        assert d['service_name'] == 'HTTP'
        assert d['service_type'] == 'Web'

    def test_attack_subdocument(self):
        doc = event_to_document(self._sample_event())
        a = doc['attack']
        assert a['label'] == 'DoS Hulk'
        assert a['category'] == 'DoS'
        assert a['severity'] == 'HIGH'
        assert a['is_attack'] is True

    def test_benign_not_attack(self):
        doc = event_to_document(self._sample_event(
            label='BENIGN', attack_category='Normal', severity='LOW'
        ))
        assert doc['attack']['is_attack'] is False

    def test_protocol_subdocument(self):
        doc = event_to_document(self._sample_event())
        p = doc['protocol']
        assert p['name'] == 'TCP'
        assert p['transport_layer'] == 'Transport'

    def test_metrics_subdocument(self):
        doc = event_to_document(self._sample_event())
        m = doc['metrics']
        assert m['flow_duration'] == 5000
        assert m['fwd_packets'] == 10
        assert m['bwd_packets'] == 5
        assert m['fwd_bytes'] == 2048
        assert m['bwd_bytes'] == 512
        assert m['flow_bytes_per_sec'] == 100.5
        assert m['flow_pkts_per_sec'] == 10.0

    def test_unknown_port_service(self):
        doc = event_to_document(self._sample_event(destination_port=55555))
        assert doc['destination']['service_name'] == 'Unknown'
        assert doc['destination']['service_type'] == 'Unknown'

    def test_missing_timestamp_defaults_to_now(self):
        doc = event_to_document(self._sample_event(timestamp=''))
        assert isinstance(doc['timestamp'], datetime)

    def test_iso_z_format_parsed(self):
        doc = event_to_document(self._sample_event(timestamp='2017-07-05T10:30:00Z'))
        assert doc['timestamp'].hour == 10

    def test_weekend_detection(self):
        doc = event_to_document(self._sample_event(timestamp='2017-07-08T10:00:00'))
        assert doc['time']['is_weekend'] is True
        assert doc['time']['day_of_week'] == 'Saturday'
