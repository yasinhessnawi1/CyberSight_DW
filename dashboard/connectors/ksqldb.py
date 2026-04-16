"""
CyberSight DW — ksqlDB Dashboard Connector
Queries ksqlDB materialized views via the REST API for real-time metrics.
"""

import os
import logging

import pandas as pd
import requests

logger = logging.getLogger(__name__)

KSQLDB_URL = os.environ.get('KSQLDB_URL', 'http://ksqldb-server:8088')


class KsqlDBConnector:
    def __init__(self, base_url: str = KSQLDB_URL):
        self.base_url = base_url.rstrip('/')

    def _pull_query(self, sql: str) -> pd.DataFrame:
        """Execute a pull query against a ksqlDB materialized view."""
        try:
            payload = {'ksql': sql, 'streamsProperties': {}}
            r = requests.post(
                f'{self.base_url}/query',
                json=payload,
                timeout=5,
                headers={'Accept': 'application/vnd.ksql.v1+json'},
            )
            if r.status_code != 200:
                logger.warning("ksqlDB query failed (%d): %s", r.status_code, r.text[:200])
                return pd.DataFrame()

            data = r.json()
            if not data or len(data) < 2:
                return pd.DataFrame()

            header = data[0].get('header', {}).get('schema', '')
            col_names = [
                c.strip().split('`')[1] if '`' in c else c.strip().split(' ')[0]
                for c in header.split(',')
            ] if header else []

            rows = []
            for item in data[1:]:
                row = item.get('row', {}).get('columns')
                if row:
                    rows.append(row)

            if not rows:
                return pd.DataFrame()

            return pd.DataFrame(rows, columns=col_names[:len(rows[0])] if col_names else None)

        except requests.exceptions.ConnectionError:
            logger.debug("ksqlDB not reachable")
            return pd.DataFrame()
        except Exception as e:
            logger.warning("ksqlDB query error: %s", e)
            return pd.DataFrame()

    def is_available(self) -> bool:
        try:
            r = requests.get(f'{self.base_url}/info', timeout=3)
            return r.status_code == 200
        except Exception:
            return False

    def get_attack_rate_1min(self) -> pd.DataFrame:
        return self._pull_query(
            "SELECT * FROM ATTACK_RATE_1MIN;"
        )

    def get_protocol_rate_1min(self) -> pd.DataFrame:
        return self._pull_query(
            "SELECT * FROM PROTOCOL_RATE_1MIN;"
        )

    def get_high_volume_sources(self) -> pd.DataFrame:
        return self._pull_query(
            "SELECT * FROM HIGH_VOLUME_SOURCES;"
        )
