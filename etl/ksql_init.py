"""
CyberSight DW — ksqlDB Initializer
Reads sql/ksql_init.sql and POSTs each statement to the ksqlDB REST API.
Run as a one-shot service via docker-compose.
"""

import os
import sys
import time
import logging
from typing import Optional

import requests

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
logger = logging.getLogger('ksql_init')

KSQLDB_URL = os.environ.get('KSQLDB_URL', 'http://127.0.0.1:8088')
SQL_PATH = os.environ.get('KSQL_SQL_PATH', '/app/sql/ksql_init.sql')
MAX_RETRIES = 30
RETRY_DELAY = 5


def wait_for_ksqldb():
    last_err: Optional[Exception] = None
    for attempt in range(MAX_RETRIES):
        try:
            r = requests.get(f'{KSQLDB_URL}/info', timeout=5)
            if r.status_code == 200:
                logger.info("ksqlDB is ready")
                return
            last_err = RuntimeError(f"HTTP {r.status_code}")
        except Exception as e:
            last_err = e
        err_hint = f": {last_err}" if last_err else ""
        logger.warning("ksqlDB not ready (attempt %d/%d)%s", attempt + 1, MAX_RETRIES, err_hint)
        time.sleep(RETRY_DELAY)
    logger.error("ksqlDB not reachable after %d attempts (last error: %s)", MAX_RETRIES, last_err)
    sys.exit(1)


def execute_statements(sql: str, retries: int = 3):
    """Send one or more semicolon-delimited statements to ksqlDB."""
    payload = {'ksql': sql, 'streamsProperties': {}}
    for attempt in range(1, retries + 1):
        try:
            r = requests.post(f'{KSQLDB_URL}/ksql', json=payload, timeout=120)
            if r.status_code == 200:
                results = r.json() if r.text else []
                for item in results:
                    status = item.get('commandStatus', {}).get('status', 'OK')
                    stmt_text = item.get('statementText', '')[:80].replace('\n', ' ')
                    logger.info("OK [%s]: %s...", status, stmt_text)
                return True
            body = r.text[:400]
            if 'already exists' in body.lower():
                logger.info("Already exists (OK)")
                return True
            if attempt < retries and ('does not exist' in body.lower()
                                      or 'timeout' in body.lower()):
                logger.warning("Retryable error (attempt %d/%d), retrying in 10s: %s",
                               attempt, retries, body[:200])
                time.sleep(10)
                continue
            logger.warning("ksqlDB returned %d: %s", r.status_code, body)
            return False
        except requests.exceptions.ReadTimeout:
            logger.warning("Request timed out (attempt %d/%d)", attempt, retries)
            time.sleep(5)
        except Exception as e:
            logger.error("Failed to execute ksqlDB statements: %s", e)
            return False
    logger.error("All %d attempts failed", retries)
    return False


def main():
    wait_for_ksqldb()

    if not os.path.exists(SQL_PATH):
        alt = os.path.join(os.path.dirname(__file__), '..', 'sql', 'ksql_init.sql')
        if os.path.exists(alt):
            sql_path = alt
        else:
            logger.error("ksql_init.sql not found at %s or %s", SQL_PATH, alt)
            sys.exit(1)
    else:
        sql_path = SQL_PATH

    with open(sql_path, 'r') as f:
        content = f.read()

    stripped_lines = []
    for line in content.split('\n'):
        s = line.strip()
        if s.startswith('--') or not s:
            continue
        stripped_lines.append(line)

    statements = []
    current_parts = []
    for line in stripped_lines:
        current_parts.append(line)
        if line.rstrip().endswith(';'):
            statements.append('\n'.join(current_parts))
            current_parts = []

    logger.info("Found %d ksqlDB statements, sending one at a time...", len(statements))

    for i, stmt in enumerate(statements):
        logger.info("Sending statement %d/%d: %s...", i + 1, len(statements),
                     stmt[:80].replace('\n', ' '))
        success = execute_statements(stmt)
        if not success:
            logger.warning("Statement %d failed, continuing with next...", i + 1)
        time.sleep(5)

    logger.info("ksqlDB initialization complete")


if __name__ == '__main__':
    main()
