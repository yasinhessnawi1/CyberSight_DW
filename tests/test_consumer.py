"""Unit tests for etl/consumer.py — dimension upsert logic and helper functions."""

import sys
import os
from unittest.mock import MagicMock, patch
from datetime import datetime

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'etl'))

from consumer import (
    upsert_dim_time,
    upsert_dim_source,
    upsert_dim_destination,
    upsert_dim_attack,
    upsert_dim_protocol,
    insert_fact,
)


class TestUpsertDimTime:
    def _sample_event(self):
        return {'timestamp': '2017-07-05T10:30:00'}

    def test_new_insert_returns_key(self):
        cur = MagicMock()
        cur.fetchone.return_value = (42,)
        result = upsert_dim_time(cur, self._sample_event())
        assert result == 42
        cur.execute.assert_called_once()

    def test_conflict_does_select(self):
        cur = MagicMock()
        cur.fetchone.side_effect = [None, (99,)]
        result = upsert_dim_time(cur, self._sample_event())
        assert result == 99
        assert cur.execute.call_count == 2

    def test_z_timestamp_parsed(self):
        cur = MagicMock()
        cur.fetchone.return_value = (1,)
        event = {'timestamp': '2017-07-05T10:30:00Z'}
        result = upsert_dim_time(cur, event)
        assert result == 1

    def test_sql_contains_insert(self):
        cur = MagicMock()
        cur.fetchone.return_value = (1,)
        upsert_dim_time(cur, self._sample_event())
        sql = cur.execute.call_args[0][0]
        assert 'INSERT INTO dim_time' in sql


class TestUpsertDimSource:
    def _sample_event(self):
        return {
            'source_ip': '192.168.1.1',
            'source_port': 12345,
            'source_country': 'China',
            'source_region': 'Asia',
        }

    def test_new_insert_returns_key(self):
        cur = MagicMock()
        cur.fetchone.return_value = (10,)
        result = upsert_dim_source(cur, self._sample_event())
        assert result == 10

    def test_conflict_select(self):
        cur = MagicMock()
        cur.fetchone.side_effect = [None, (20,)]
        result = upsert_dim_source(cur, self._sample_event())
        assert result == 20

    def test_sql_contains_insert(self):
        cur = MagicMock()
        cur.fetchone.return_value = (1,)
        upsert_dim_source(cur, self._sample_event())
        sql = cur.execute.call_args[0][0]
        assert 'INSERT INTO dim_source' in sql


class TestUpsertDimDestination:
    def _sample_event(self):
        return {
            'destination_ip': '10.0.0.1',
            'destination_port': 80,
        }

    def test_new_insert_returns_key(self):
        cur = MagicMock()
        cur.fetchone.return_value = (5,)
        result = upsert_dim_destination(cur, self._sample_event())
        assert result == 5

    def test_service_name_assigned(self):
        cur = MagicMock()
        cur.fetchone.return_value = (1,)
        upsert_dim_destination(cur, self._sample_event())
        args = cur.execute.call_args[0][1]
        assert 'HTTP' in args


class TestUpsertDimAttack:
    def _sample_event(self):
        return {
            'label': 'DoS Hulk',
            'attack_category': 'DoS',
            'severity': 'HIGH',
        }

    def test_new_insert_returns_key(self):
        cur = MagicMock()
        cur.fetchone.return_value = (3,)
        result = upsert_dim_attack(cur, self._sample_event())
        assert result == 3

    def test_invalid_severity_defaults_to_low(self):
        cur = MagicMock()
        cur.fetchone.return_value = (1,)
        event = {'label': 'Test', 'attack_category': 'Test', 'severity': 'INVALID'}
        upsert_dim_attack(cur, event)
        args = cur.execute.call_args[0][1]
        assert 'LOW' in args


class TestUpsertDimProtocol:
    def test_new_insert_returns_key(self):
        cur = MagicMock()
        cur.fetchone.return_value = (2,)
        event = {'protocol': 'TCP'}
        result = upsert_dim_protocol(cur, event)
        assert result == 2


class TestInsertFact:
    def test_executes_insert(self):
        cur = MagicMock()
        event = {
            'attack_category': 'DoS',
            'flow_duration': 5000,
            'fwd_packets': 10,
            'bwd_packets': 5,
            'fwd_bytes': 2048,
            'bwd_bytes': 512,
            'flow_bytes_per_sec': 100.5,
            'flow_packets_per_sec': 10.0,
        }
        insert_fact(cur, event, 1, 2, 3, 4, 5)
        cur.execute.assert_called_once()
        sql = cur.execute.call_args[0][0]
        assert 'INSERT INTO fact_network_event' in sql

    def test_is_attack_true_for_dos(self):
        cur = MagicMock()
        event = {
            'attack_category': 'DoS',
            'flow_duration': 0, 'fwd_packets': 0, 'bwd_packets': 0,
            'fwd_bytes': 0, 'bwd_bytes': 0,
            'flow_bytes_per_sec': 0, 'flow_packets_per_sec': 0,
        }
        insert_fact(cur, event, 1, 2, 3, 4, 5)
        args = cur.execute.call_args[0][1]
        assert args[-1] is True  # is_attack should be True

    def test_is_attack_false_for_normal(self):
        cur = MagicMock()
        event = {
            'attack_category': 'Normal',
            'flow_duration': 0, 'fwd_packets': 0, 'bwd_packets': 0,
            'fwd_bytes': 0, 'bwd_bytes': 0,
            'flow_bytes_per_sec': 0, 'flow_packets_per_sec': 0,
        }
        insert_fact(cur, event, 1, 2, 3, 4, 5)
        args = cur.execute.call_args[0][1]
        assert args[-1] is False
