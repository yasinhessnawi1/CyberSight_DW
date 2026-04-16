"""Unit tests for etl/clean.py — data cleaning pipeline."""

import sys
import os
import struct
import socket

import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'etl'))

from clean import (
    decimal_to_ip,
    normalise_columns,
    reconstruct_timestamps,
    clean_dataframe,
)


class TestDecimalToIp:
    def test_valid_ip(self):
        ip_int = struct.unpack('>I', socket.inet_aton('192.168.1.1'))[0]
        assert decimal_to_ip(ip_int) == '192.168.1.1'

    def test_loopback(self):
        ip_int = struct.unpack('>I', socket.inet_aton('127.0.0.1'))[0]
        assert decimal_to_ip(ip_int) == '127.0.0.1'

    def test_zero_returns_fallback(self):
        assert decimal_to_ip(0) == '0.0.0.0'

    def test_negative_returns_fallback(self):
        assert decimal_to_ip(-1) == '0.0.0.0'

    def test_overflow_returns_fallback(self):
        assert decimal_to_ip(0xFFFFFFFF + 1) == '0.0.0.0'

    def test_string_input(self):
        ip_int = struct.unpack('>I', socket.inet_aton('10.0.0.1'))[0]
        assert decimal_to_ip(str(ip_int)) == '10.0.0.1'

    def test_float_input(self):
        ip_int = struct.unpack('>I', socket.inet_aton('10.0.0.1'))[0]
        assert decimal_to_ip(float(ip_int)) == '10.0.0.1'

    def test_invalid_string_returns_fallback(self):
        assert decimal_to_ip('not_a_number') == '0.0.0.0'

    def test_none_returns_fallback(self):
        assert decimal_to_ip(None) == '0.0.0.0'


class TestNormaliseColumns:
    def test_strips_whitespace(self):
        df = pd.DataFrame({' Source IP ': [1], ' Label': [2]})
        result = normalise_columns(df)
        assert 'Source IP' in result.columns
        assert 'Label' in result.columns

    def test_renames_hf_columns(self):
        df = pd.DataFrame({
            'Src IP dec': [1],
            'Dst IP dec': [2],
            'Src Port': [80],
            'Dst Port': [443],
        })
        result = normalise_columns(df)
        assert 'Source IP' in result.columns
        assert 'Destination IP' in result.columns
        assert 'Source Port' in result.columns
        assert 'Destination Port' in result.columns

    def test_preserves_existing_columns(self):
        df = pd.DataFrame({'Source IP': ['1.2.3.4'], 'Label': ['BENIGN']})
        result = normalise_columns(df)
        assert list(result.columns) == ['Source IP', 'Label']


class TestReconstructTimestamps:
    def test_monday_date(self):
        df = pd.DataFrame({'x': range(10)})
        ts = reconstruct_timestamps(df, 'monday.csv')
        assert ts[0].date() == pd.Timestamp('2017-07-03').date()
        assert ts[0].hour == 8

    def test_friday_date(self):
        df = pd.DataFrame({'x': range(10)})
        ts = reconstruct_timestamps(df, 'friday.csv')
        assert ts[0].date() == pd.Timestamp('2017-07-07').date()

    def test_output_length_matches_input(self):
        df = pd.DataFrame({'x': range(100)})
        ts = reconstruct_timestamps(df, 'tuesday.csv')
        assert len(ts) == 100

    def test_timestamps_within_working_hours(self):
        df = pd.DataFrame({'x': range(50)})
        ts = reconstruct_timestamps(df, 'wednesday.csv')
        for t in ts:
            assert 8 <= t.hour <= 17

    def test_unknown_filename_defaults_to_monday(self):
        df = pd.DataFrame({'x': range(5)})
        ts = reconstruct_timestamps(df, 'unknown_file.csv')
        assert ts[0].date() == pd.Timestamp('2017-07-03').date()


class TestCleanDataframe:
    def _make_raw_df(self, n=10):
        return pd.DataFrame({
            'Source IP': ['192.168.1.1'] * n,
            'Destination IP': ['10.0.0.1'] * n,
            'Source Port': [12345] * n,
            'Destination Port': [80] * n,
            'Protocol': [6] * n,
            'Timestamp': pd.date_range('2017-07-03 09:00', periods=n, freq='min'),
            'Flow Duration': [1000] * n,
            'Total Fwd Packets': [10] * n,
            'Total Backward Packets': [5] * n,
            'Label': ['BENIGN'] * n,
            'Flow Bytes/s': [100.0] * n,
            'Flow Packets/s': [10.0] * n,
        })

    def test_returns_dataframe(self):
        df = self._make_raw_df()
        result = clean_dataframe(df, 'monday.csv')
        assert isinstance(result, pd.DataFrame)

    def test_adds_attack_category(self):
        df = self._make_raw_df()
        result = clean_dataframe(df)
        assert 'attack_category' in result.columns

    def test_adds_severity(self):
        df = self._make_raw_df()
        result = clean_dataframe(df)
        assert 'severity' in result.columns

    def test_adds_geo_columns(self):
        df = self._make_raw_df()
        result = clean_dataframe(df)
        assert 'source_country' in result.columns
        assert 'source_region' in result.columns

    def test_benign_label_categorised_as_normal(self):
        df = self._make_raw_df()
        result = clean_dataframe(df)
        assert all(result['attack_category'] == 'Normal')
        assert all(result['severity'] == 'LOW')

    def test_protocol_decoded(self):
        df = self._make_raw_df()
        result = clean_dataframe(df)
        assert all(result['Protocol'] == 'TCP')

    def test_infinity_replaced(self):
        df = self._make_raw_df()
        df.loc[0, 'Flow Bytes/s'] = np.inf
        df.loc[1, 'Flow Bytes/s'] = -np.inf
        result = clean_dataframe(df)
        assert not np.isinf(result['Flow Bytes/s']).any()

    def test_nan_critical_fields_dropped(self):
        df = self._make_raw_df()
        df.loc[0, 'Source IP'] = np.nan
        result = clean_dataframe(df)
        assert len(result) == 9

    def test_dos_label_categorised(self):
        df = self._make_raw_df(5)
        df['Label'] = 'DoS Hulk'
        result = clean_dataframe(df)
        assert all(result['attack_category'] == 'DoS')
        assert all(result['severity'] == 'HIGH')

    def test_ddos_label_categorised(self):
        df = self._make_raw_df(3)
        df['Label'] = 'DDoS'
        result = clean_dataframe(df)
        assert all(result['attack_category'] == 'DDoS')
        assert all(result['severity'] == 'CRITICAL')

    def test_web_attack_label_normalised(self):
        df = self._make_raw_df(2)
        df['Label'] = 'Web Attack \u2013 Brute Force'
        result = clean_dataframe(df)
        assert all(result['Label'] == 'Web Attack -- Brute Force')
        assert all(result['attack_category'] == 'Web Attack')

    def test_geo_deterministic(self):
        df = self._make_raw_df(5)
        result1 = clean_dataframe(df.copy())
        result2 = clean_dataframe(df.copy())
        assert list(result1['source_country']) == list(result2['source_country'])
        assert list(result1['source_region']) == list(result2['source_region'])

    def test_decimal_ip_conversion(self):
        ip_int = struct.unpack('>I', socket.inet_aton('192.168.1.1'))[0]
        df = pd.DataFrame({
            'Source IP': [str(ip_int)] * 5,
            'Destination IP': [str(ip_int)] * 5,
            'Source Port': [80] * 5,
            'Destination Port': [443] * 5,
            'Protocol': [6] * 5,
            'Timestamp': pd.date_range('2017-07-03 09:00', periods=5, freq='min'),
            'Label': ['BENIGN'] * 5,
        })
        result = clean_dataframe(df, 'monday.csv')
        assert all(result['Source IP'] == '192.168.1.1')
