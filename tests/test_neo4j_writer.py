"""Unit tests for etl/neo4j_writer.py — aggregation logic (no real Neo4j needed)."""

import sys
import os
from collections import defaultdict
from unittest.mock import MagicMock, patch
from datetime import datetime

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'etl'))


class TestNeo4jWriterAggregation:
    """Test the in-memory aggregation logic of Neo4jWriter.write_batch."""

    def _sample_events(self, n=5, label='DoS Hulk', category='DoS',
                       severity='HIGH', protocol='TCP'):
        events = []
        for i in range(n):
            events.append({
                'source_ip': f'192.168.1.{i % 3 + 1}',
                'destination_ip': f'10.0.0.{i % 2 + 1}',
                'label': label,
                'attack_category': category,
                'severity': severity,
                'protocol': protocol,
                'timestamp': f'2017-07-05T{10 + i % 9:02d}:30:00',
                'source_country': 'China',
                'source_region': 'Asia',
                'destination_port': 80,
                'fwd_bytes': 1024,
                'bwd_bytes': 512,
            })
        return events

    @patch('neo4j_writer.GraphDatabase')
    def test_write_batch_calls_all_write_methods(self, mock_gdb):
        mock_driver = MagicMock()
        mock_gdb.driver.return_value = mock_driver
        mock_session = MagicMock()
        mock_driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_driver.session.return_value.__exit__ = MagicMock(return_value=False)
        mock_session.run.return_value = MagicMock()
        mock_session.run.return_value.single.return_value = {'cnt': 0}

        from neo4j_writer import Neo4jWriter
        writer = Neo4jWriter.__new__(Neo4jWriter)
        writer.driver = mock_driver

        writer._write_attacked = MagicMock()
        writer._write_used_attack = MagicMock()
        writer._write_targeted_by = MagicMock()
        writer._write_used_protocol = MagicMock()
        writer._write_active_in = MagicMock()

        events = self._sample_events()
        writer.write_batch(events)

        writer._write_attacked.assert_called_once()
        writer._write_used_attack.assert_called_once()
        writer._write_targeted_by.assert_called_once()
        writer._write_used_protocol.assert_called_once()
        writer._write_active_in.assert_called_once()

    @patch('neo4j_writer.GraphDatabase')
    def test_aggregation_counts(self, mock_gdb):
        mock_driver = MagicMock()
        mock_gdb.driver.return_value = mock_driver
        mock_session = MagicMock()
        mock_driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_driver.session.return_value.__exit__ = MagicMock(return_value=False)

        from neo4j_writer import Neo4jWriter
        writer = Neo4jWriter.__new__(Neo4jWriter)
        writer.driver = mock_driver

        attacked_agg = {}
        original_write_attacked = None

        def capture_attacked(agg):
            attacked_agg.update(agg)

        writer._write_attacked = capture_attacked
        writer._write_used_attack = MagicMock()
        writer._write_targeted_by = MagicMock()
        writer._write_used_protocol = MagicMock()
        writer._write_active_in = MagicMock()

        events = [
            {
                'source_ip': '1.1.1.1', 'destination_ip': '2.2.2.2',
                'label': 'DoS', 'attack_category': 'DoS', 'severity': 'HIGH',
                'protocol': 'TCP', 'timestamp': '2017-07-05T10:00:00',
                'source_country': 'China', 'source_region': 'Asia',
                'destination_port': 80, 'fwd_bytes': 100, 'bwd_bytes': 50,
            },
            {
                'source_ip': '1.1.1.1', 'destination_ip': '2.2.2.2',
                'label': 'DoS', 'attack_category': 'DoS', 'severity': 'HIGH',
                'protocol': 'TCP', 'timestamp': '2017-07-05T10:01:00',
                'source_country': 'China', 'source_region': 'Asia',
                'destination_port': 80, 'fwd_bytes': 200, 'bwd_bytes': 100,
            },
        ]
        writer.write_batch(events)

        key = ('1.1.1.1', '2.2.2.2', 'China', 'Asia', 'HTTP', 'Web')
        assert key in attacked_agg
        assert attacked_agg[key]['cnt'] == 2
        assert attacked_agg[key]['total_bytes'] == 450  # (100+50) + (200+100)

    @patch('neo4j_writer.GraphDatabase')
    def test_day_of_week_used_in_active_in(self, mock_gdb):
        """Verify the fixed bug: active_in uses day_of_week, not day-of-month."""
        mock_driver = MagicMock()
        mock_gdb.driver.return_value = mock_driver
        mock_session = MagicMock()
        mock_driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_driver.session.return_value.__exit__ = MagicMock(return_value=False)

        from neo4j_writer import Neo4jWriter
        writer = Neo4jWriter.__new__(Neo4jWriter)
        writer.driver = mock_driver

        active_in_agg = {}

        def capture_active_in(agg):
            active_in_agg.update(agg)

        writer._write_attacked = MagicMock()
        writer._write_used_attack = MagicMock()
        writer._write_targeted_by = MagicMock()
        writer._write_used_protocol = MagicMock()
        writer._write_active_in = capture_active_in

        events = [{
            'source_ip': '1.1.1.1', 'destination_ip': '2.2.2.2',
            'label': 'DoS', 'attack_category': 'DoS', 'severity': 'HIGH',
            'protocol': 'TCP', 'timestamp': '2017-07-05T10:00:00',
            'source_country': 'China', 'source_region': 'Asia',
            'destination_port': 80, 'fwd_bytes': 100, 'bwd_bytes': 50,
        }]
        writer.write_batch(events)

        for key in active_in_agg:
            day_val = key[4]  # (label, category, severity, hour_bucket, day_of_week, month, year)
            ts = datetime.fromisoformat('2017-07-05T10:00:00')
            assert day_val == ts.weekday()  # Wednesday = 2
            assert day_val != ts.day  # NOT 5 (day of month)
