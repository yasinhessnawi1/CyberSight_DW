"""
CyberSight DW — Kafka Consumer (Multi-Backend)
Consumes events from Kafka and writes to PostgreSQL, MongoDB, and Neo4j
simultaneously. Uses batched inserts with manual commit for throughput.
Neo4j writes run in a background thread to avoid bottlenecking the pipeline.
"""

import os
import sys
import json
import time
import logging
import threading
import queue
from datetime import datetime

import psycopg2
import psycopg2.extras
from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import NoBrokersAvailable

from mongo_writer import MongoWriter
from neo4j_writer import Neo4jWriter
from mappings import (
    SERVICE_MAP, VALID_SEVERITIES,
    classify_ip, time_of_day, get_transport_layer,
)

from logging_config import setup_logging

setup_logging("consumer")
logger = logging.getLogger('consumer')

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
KAFKA_BOOTSTRAP = os.environ.get('KAFKA_BOOTSTRAP', 'kafka:9092')
TOPIC = 'network-events'
DLQ_TOPIC = 'network-events-dlq'
GROUP_ID = 'cybersight-etl'
BATCH_SIZE = int(os.environ.get('BATCH_SIZE', '1000'))

PG_HOST = os.environ.get('PG_HOST', 'postgres')
PG_PORT = int(os.environ.get('PG_PORT', '5432'))
PG_DB = os.environ.get('PG_DB', 'cybersight')
PG_USER = os.environ.get('PG_USER', 'postgres')
PG_PASSWORD = os.environ.get('PG_PASSWORD', 'postgres')

MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://mongodb:27017')
NEO4J_URI = os.environ.get('NEO4J_URI', 'bolt://neo4j:7687')
NEO4J_USER = os.environ.get('NEO4J_USER', 'neo4j')
NEO4J_PASSWORD = os.environ.get('NEO4J_PASSWORD', 'password')

BATCH_JOB_INTERVAL = 10000


# ---------------------------------------------------------------------------
# Wait for services
# ---------------------------------------------------------------------------

def wait_for_services():
    """Wait for Kafka and PostgreSQL to be ready."""
    for attempt in range(30):
        try:
            conn = psycopg2.connect(
                host=PG_HOST, port=PG_PORT, dbname=PG_DB, user=PG_USER, password=PG_PASSWORD
            )
            conn.close()
            logger.info("PostgreSQL is ready")
            break
        except psycopg2.OperationalError:
            logger.warning("PostgreSQL not ready (attempt %d/30)", attempt + 1)
            time.sleep(5)
    else:
        logger.error("PostgreSQL not reachable")
        sys.exit(1)

    for attempt in range(30):
        try:
            c = KafkaConsumer(bootstrap_servers=KAFKA_BOOTSTRAP)
            c.close()
            logger.info("Kafka is ready")
            return
        except NoBrokersAvailable:
            logger.warning("Kafka not ready (attempt %d/30)", attempt + 1)
            time.sleep(5)
    logger.error("Kafka not reachable")
    sys.exit(1)


# ---------------------------------------------------------------------------
# PostgreSQL dimension upserts
# ---------------------------------------------------------------------------

def upsert_dim_time(cur, event: dict) -> int:
    ts_str = event['timestamp']
    try:
        ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
    except (ValueError, AttributeError):
        ts = datetime.strptime(ts_str[:19], '%Y-%m-%dT%H:%M:%S')

    ts_truncated = ts.replace(second=0, microsecond=0)
    day_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
    dow = ts.weekday()

    cur.execute("""
        INSERT INTO dim_time (timestamp, hour, day, week, month, year, day_of_week, is_weekend, time_of_day)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (timestamp) DO NOTHING
        RETURNING time_key
    """, (ts_truncated, ts.hour, ts.day, ts.isocalendar()[1], ts.month, ts.year,
          day_names[dow], dow >= 5, time_of_day(ts.hour)))

    row = cur.fetchone()
    if row:
        return row[0]
    cur.execute("SELECT time_key FROM dim_time WHERE timestamp = %s", (ts_truncated,))
    return cur.fetchone()[0]


def upsert_dim_source(cur, event: dict) -> int:
    ip = event['source_ip']
    port = int(event['source_port'])
    country = event.get('source_country', 'Unknown')
    region = event.get('source_region', 'Unknown')

    cur.execute("""
        INSERT INTO dim_source (source_ip, source_port, country, region, ip_class)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT (source_ip, source_port) DO NOTHING
        RETURNING source_key
    """, (ip, port, country, region, classify_ip(ip)))

    row = cur.fetchone()
    if row:
        return row[0]
    cur.execute("SELECT source_key FROM dim_source WHERE source_ip = %s AND source_port = %s", (ip, port))
    return cur.fetchone()[0]


def upsert_dim_destination(cur, event: dict) -> int:
    ip = event['destination_ip']
    port = int(event['destination_port'])
    svc = SERVICE_MAP.get(port, ('Unknown', 'Unknown'))

    cur.execute("""
        INSERT INTO dim_destination (dest_ip, dest_port, service_name, service_type)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (dest_ip, dest_port) DO NOTHING
        RETURNING dest_key
    """, (ip, port, svc[0], svc[1]))

    row = cur.fetchone()
    if row:
        return row[0]
    cur.execute("SELECT dest_key FROM dim_destination WHERE dest_ip = %s AND dest_port = %s", (ip, port))
    return cur.fetchone()[0]


def upsert_dim_attack(cur, event: dict) -> int:
    label = event['label']
    category = event.get('attack_category', 'Unknown')
    severity = event.get('severity', 'LOW')
    if severity not in VALID_SEVERITIES:
        severity = 'LOW'

    cur.execute("""
        INSERT INTO dim_attack (attack_label, attack_category, severity)
        VALUES (%s, %s, %s)
        ON CONFLICT (attack_label) DO NOTHING
        RETURNING attack_key
    """, (label, category, severity))

    row = cur.fetchone()
    if row:
        return row[0]
    cur.execute("SELECT attack_key FROM dim_attack WHERE attack_label = %s", (label,))
    return cur.fetchone()[0]


def upsert_dim_protocol(cur, event: dict) -> int:
    protocol = event['protocol']
    transport = get_transport_layer(protocol)

    cur.execute("""
        INSERT INTO dim_protocol (protocol_name, transport_layer)
        VALUES (%s, %s)
        ON CONFLICT (protocol_name) DO NOTHING
        RETURNING protocol_key
    """, (protocol, transport))

    row = cur.fetchone()
    if row:
        return row[0]
    cur.execute("SELECT protocol_key FROM dim_protocol WHERE protocol_name = %s", (protocol,))
    return cur.fetchone()[0]


def insert_fact(cur, event: dict, time_key: int, source_key: int,
                dest_key: int, attack_key: int, protocol_key: int):
    is_attack = event.get('attack_category', 'Normal') != 'Normal'
    cur.execute("""
        INSERT INTO fact_network_event
            (time_key, source_key, dest_key, attack_key, protocol_key,
             flow_duration, fwd_packets, bwd_packets, fwd_bytes, bwd_bytes,
             flow_bytes_per_sec, flow_pkts_per_sec, is_attack)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (
        time_key, source_key, dest_key, attack_key, protocol_key,
        int(event.get('flow_duration', 0)),
        int(event.get('fwd_packets', 0)),
        int(event.get('bwd_packets', 0)),
        int(event.get('fwd_bytes', 0)),
        int(event.get('bwd_bytes', 0)),
        float(event.get('flow_bytes_per_sec', 0)),
        float(event.get('flow_packets_per_sec', 0)),
        is_attack,
    ))


# ---------------------------------------------------------------------------
# DLQ
# ---------------------------------------------------------------------------

def create_dlq_producer():
    try:
        return KafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP,
            value_serializer=lambda v: json.dumps(v, default=str).encode('utf-8'),
        )
    except Exception as e:
        logger.error("Failed to create DLQ producer: %s", e)
        return None


def send_to_dlq(dlq_producer, event: dict, error_msg: str):
    if dlq_producer is None:
        return
    try:
        event['_error'] = error_msg
        dlq_producer.send(DLQ_TOPIC, value=event)
    except Exception as e:
        logger.error("Failed to send to DLQ: %s", e)


# ---------------------------------------------------------------------------
# Batch aggregation SQL
# ---------------------------------------------------------------------------

def run_batch_jobs(conn):
    """Execute the pre-aggregation batch SQL scripts."""
    batch_files = [
        '/app/sql/batch_hourly.sql',
        '/app/sql/batch_sources.sql',
        '/app/sql/batch_protocol_daily.sql',
        '/app/sql/batch_severity_daily.sql',
        '/app/sql/batch_dest_port.sql',
        '/app/sql/batch_weekend.sql',
    ]
    for fpath in batch_files:
        local = fpath.replace('/app/sql/', '')
        alt_path = os.path.join(os.path.dirname(__file__), '..', 'sql', local)
        actual_path = fpath if os.path.exists(fpath) else alt_path
        if not os.path.exists(actual_path):
            logger.warning("Batch SQL not found: %s", actual_path)
            continue
        try:
            with open(actual_path, 'r') as f:
                sql = f.read()
            with conn.cursor() as cur:
                cur.execute(sql)
            conn.commit()
            logger.info("Batch job completed: %s", local)
        except Exception as e:
            conn.rollback()
            logger.error("Batch job failed (%s): %s", local, e)


# ---------------------------------------------------------------------------
# Neo4j background writer thread
# ---------------------------------------------------------------------------

class Neo4jBackgroundWriter:
    """Offloads Neo4j writes to a background thread so they don't block PG/Mongo."""

    def __init__(self, neo4j_writer: Neo4jWriter):
        self.writer = neo4j_writer
        self._queue = queue.Queue(maxsize=50)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        while not self._stop.is_set():
            try:
                batch = self._queue.get(timeout=2)
                if batch is None:
                    break
                self.writer.write_batch(batch)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error("Neo4j background write failed: %s", e)

    def enqueue(self, events: list[dict]):
        try:
            self._queue.put(events, timeout=10)
        except queue.Full:
            logger.warning("Neo4j write queue full — dropping batch of %d", len(events))

    def finish(self):
        self._queue.put(None)
        self._stop.set()
        self._thread.join(timeout=60)


# ---------------------------------------------------------------------------
# Batch processing
# ---------------------------------------------------------------------------

def ensure_pg_connection(conn):
    """Return a healthy PG connection, reconnecting if necessary."""
    try:
        conn.isolation_level
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
        return conn
    except Exception:
        logger.warning("PG connection lost, reconnecting...")
        try:
            conn.close()
        except Exception:
            pass
        new_conn = psycopg2.connect(
            host=PG_HOST, port=PG_PORT, dbname=PG_DB,
            user=PG_USER, password=PG_PASSWORD,
        )
        new_conn.autocommit = False
        logger.info("PG reconnected successfully")
        return new_conn


def process_pg_batch(conn, batch: list, dlq_producer) -> tuple[int, 'psycopg2.connection']:
    """Write batch to PostgreSQL. Returns (count_inserted, connection)."""
    conn = ensure_pg_connection(conn)
    try:
        with conn.cursor() as cur:
            for event in batch:
                time_key = upsert_dim_time(cur, event)
                source_key = upsert_dim_source(cur, event)
                dest_key = upsert_dim_destination(cur, event)
                attack_key = upsert_dim_attack(cur, event)
                protocol_key = upsert_dim_protocol(cur, event)
                insert_fact(cur, event, time_key, source_key,
                            dest_key, attack_key, protocol_key)
        conn.commit()
        return len(batch), conn
    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            conn = ensure_pg_connection(conn)
        logger.error("PG batch failed (%d records): %s", len(batch), e)
        for event in batch:
            send_to_dlq(dlq_producer, event, str(e))
        return 0, conn


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    wait_for_services()

    conn = psycopg2.connect(
        host=PG_HOST, port=PG_PORT, dbname=PG_DB, user=PG_USER, password=PG_PASSWORD
    )
    conn.autocommit = False

    try:
        mongo_writer = MongoWriter(MONGO_URI)
        logger.info("MongoDB writer initialized")
    except Exception as e:
        logger.error("MongoDB init failed: %s — continuing without MongoDB", e)
        mongo_writer = None

    try:
        neo4j_writer = Neo4jWriter(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)
        neo4j_bg = Neo4jBackgroundWriter(neo4j_writer)
        logger.info("Neo4j writer initialized (background thread)")
    except Exception as e:
        logger.error("Neo4j init failed: %s — continuing without Neo4j", e)
        neo4j_writer = None
        neo4j_bg = None

    consumer = KafkaConsumer(
        TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP,
        group_id=GROUP_ID,
        value_deserializer=lambda v: json.loads(v.decode('utf-8')),
        auto_offset_reset='earliest',
        enable_auto_commit=False,
        max_poll_records=BATCH_SIZE,
        consumer_timeout_ms=60000,
        max_poll_interval_ms=1800000,
        session_timeout_ms=60000,
        heartbeat_interval_ms=10000,
        request_timeout_ms=120000,
    )

    dlq_producer = create_dlq_producer()

    total_inserted = 0
    batch = []
    start_time = time.time()
    last_batch_job = 0
    end_of_stream = False

    logger.info("Consumer started, waiting for messages...")

    try:
        while not end_of_stream:
            records = consumer.poll(timeout_ms=5000)
            if not records:
                elapsed_idle = time.time() - start_time
                if total_inserted == 0 and elapsed_idle < 600:
                    continue
                if total_inserted > 0:
                    continue
                continue

            for tp, messages in records.items():
                for message in messages:
                    event = message.value

                    if '_sentinel' in event:
                        logger.info("End-of-stream sentinel received (total from producer: %s)",
                                    event.get('total_records', '?'))
                        end_of_stream = True
                        break

                    batch.append(event)

                    if len(batch) >= BATCH_SIZE:
                        pg_count, conn = process_pg_batch(conn, batch, dlq_producer)
                        total_inserted += pg_count

                        if mongo_writer:
                            try:
                                mongo_writer.write_batch(batch)
                            except Exception as e:
                                logger.error("MongoDB batch write failed: %s", e)

                        if neo4j_bg:
                            neo4j_bg.enqueue(list(batch))

                        try:
                            consumer.commit()
                        except Exception as ce:
                            logger.warning("Kafka commit failed (non-fatal): %s", ce)
                        batch = []

                        if total_inserted - last_batch_job >= BATCH_JOB_INTERVAL:
                            last_batch_job = total_inserted
                            try:
                                conn = ensure_pg_connection(conn)
                                run_batch_jobs(conn)
                            except Exception as ex:
                                logger.error("Batch job failed at %d: %s", total_inserted, ex)

                        if total_inserted % 10000 == 0:
                            logger.info("Total inserted: %d", total_inserted)

                if end_of_stream:
                    break

        if batch:
            pg_count, conn = process_pg_batch(conn, batch, dlq_producer)
            total_inserted += pg_count
            if mongo_writer:
                try:
                    mongo_writer.write_batch(batch)
                except Exception as e:
                    logger.error("MongoDB final batch failed: %s", e)
            if neo4j_bg:
                neo4j_bg.enqueue(list(batch))
            consumer.commit()

    except KeyboardInterrupt:
        logger.info("Interrupted, flushing remaining batch...")
        if batch:
            pg_count, conn = process_pg_batch(conn, batch, dlq_producer)
            total_inserted += pg_count
            if mongo_writer:
                try:
                    mongo_writer.write_batch(batch)
                except Exception:
                    pass
            if neo4j_bg:
                neo4j_bg.enqueue(list(batch))
    finally:
        consumer.close()
        if dlq_producer:
            dlq_producer.flush()
            dlq_producer.close()

    elapsed = time.time() - start_time
    logger.info("Consumer finished: %d PG records in %.1f seconds (%.0f records/sec)",
                total_inserted, elapsed, total_inserted / max(elapsed, 1))

    logger.info("Running final batch aggregation jobs...")
    run_batch_jobs(conn)

    if neo4j_bg:
        logger.info("Waiting for Neo4j background writer to finish...")
        neo4j_bg.finish()
    if neo4j_writer:
        try:
            neo4j_writer.compute_co_attackers()
        except Exception as e:
            logger.error("Co-attacker computation failed: %s", e)
        neo4j_writer.close()

    if mongo_writer:
        mongo_writer.close()

    conn.close()
    logger.info("All done.")


if __name__ == '__main__':
    max_retries = 5
    for attempt in range(max_retries):
        try:
            main()
            break
        except Exception as e:
            logger.error("Consumer crashed (attempt %d/%d): %s", attempt + 1, max_retries, e, exc_info=True)
            if attempt < max_retries - 1:
                logger.info("Restarting consumer in 10 seconds...")
                time.sleep(10)
            else:
                logger.error("Max retries exhausted, exiting")
                sys.exit(1)
