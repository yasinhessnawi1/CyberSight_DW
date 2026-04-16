"""Unit tests for etl/geo_lookup.py — deterministic IP-to-country mapping."""

import sys
import os

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'etl'))

from geo_lookup import get_geo, _LOOKUP, COUNTRIES


class TestGeoLookup:
    def test_returns_tuple(self):
        result = get_geo('192.168.1.1')
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_country_and_region(self):
        country, region = get_geo('10.0.0.1')
        assert isinstance(country, str) and len(country) > 0
        assert isinstance(region, str) and len(region) > 0

    def test_deterministic(self):
        r1 = get_geo('192.168.1.1')
        r2 = get_geo('192.168.1.1')
        assert r1 == r2

    def test_different_ips_can_differ(self):
        results = set()
        for i in range(256):
            results.add(get_geo(f'10.0.0.{i}'))
        assert len(results) > 1

    def test_lookup_table_populated(self):
        total_weight = sum(w for _, _, w in COUNTRIES)
        assert len(_LOOKUP) == total_weight

    def test_all_countries_in_lookup(self):
        countries_in_lookup = set(c for c, _ in _LOOKUP)
        countries_in_source = set(c for c, _, _ in COUNTRIES)
        assert countries_in_lookup == countries_in_source

    def test_empty_ip(self):
        result = get_geo('')
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_known_mapping_stable(self):
        country, region = get_geo('192.168.1.1')
        assert country in [c for c, _, _ in COUNTRIES]
        assert region in [r for _, r, _ in COUNTRIES]
