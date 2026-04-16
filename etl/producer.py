"""
CyberSight DW — Kafka Producer
Reads CICIDS 2017 CSV files, cleans them, and streams records to Kafka.
Supports BULK_MODE (default: true) for fast ingestion and replay mode for demo.
Uses chunked CSV reading to avoid memory issues with large files.
"""

import os
import sys
import json
import time
import logging

import pandas as pd
from kafka import KafkaProducer
from kafka.errors import NoBrokersAvailable

from clean import clean_dataframe

from logging_config import setup_logging

setup_logging("producer")
logger = logging.getLogger('producer')

KAFKA_BOOTSTRAP = os.environ.get('KAFKA_BOOTSTRAP', 'kafka:9092')
DATA_DIR = os.environ.get('DATA_DIR', '/data/cicids2017/')
TOPIC = 'network-events'
REPLAY_SPEED = 100
BULK_MODE = os.environ.get('BULK_MODE', 'true').lower() == 'true'
CHUNK_SIZE = 50000

CSV_FILES = [
    'monday.csv',
    'tuesday.csv',
    'wednesday.csv',
    'thursday.csv',
    'friday.csv',
]


def wait_for_kafka(bootstrap: str, retries: int = 30, delay: float = 5.0):
    """Block until Kafka is reachable."""
    for attempt in range(retries):
        try:
            p = KafkaProducer(bootstrap_servers=bootstrap)
            p.close()
            logger.info("Kafka is ready")
            return
        except NoBrokersAvailable:
            logger.warning("Kafka not ready (attempt %d/%d), retrying in %.0fs...",
                           attempt + 1, retries, delay)
            time.sleep(delay)
    logger.error("Kafka not reachable after %d attempts", retries)
    sys.exit(1)


def row_to_message(row) -> dict:
    """Convert a DataFrame row (namedtuple from itertuples) to a Kafka message dict."""
    ts = getattr(row, 'Timestamp', None)
    ts_iso = ts.isoformat() if hasattr(ts, 'isoformat') else str(ts)

    return {
        'source_ip':           str(getattr(row, 'Source_IP', '0.0.0.0')),
        'source_port':         int(getattr(row, 'Source_Port', 0)),
        'destination_ip':      str(getattr(row, 'Destination_IP', '0.0.0.0')),
        'destination_port':    int(getattr(row, 'Destination_Port', 0)),
        'protocol':            str(getattr(row, 'Protocol', 'OTHER')),
        'timestamp':           ts_iso,
        'flow_duration':       int(getattr(row, 'Flow_Duration', 0)),
        'fwd_packets':         int(getattr(row, 'Total_Fwd_Packets', 0)),
        'bwd_packets':         int(getattr(row, 'Total_Backward_Packets', 0)),
        'fwd_bytes':           int(getattr(row, 'Total_Length_of_Fwd_Packets', 0)),
        'bwd_bytes':           int(getattr(row, 'Total_Length_of_Bwd_Packets', 0)),
        'flow_bytes_per_sec':  float(getattr(row, 'Flow_Bytes_s', 0)),
        'flow_packets_per_sec': float(getattr(row, 'Flow_Packets_s', 0)),
        'label':               str(getattr(row, 'Label', 'BENIGN')),
        'attack_category':     str(getattr(row, 'attack_category', 'Normal')),
        'severity':            str(getattr(row, 'severity', 'LOW')),
        'source_country':      str(getattr(row, 'source_country', 'Unknown')),
        'source_region':       str(getattr(row, 'source_region', 'Unknown')),
    }


def safe_col_name(name: str) -> str:
    """Make column name safe for namedtuple access via itertuples."""
    return name.replace(' ', '_').replace('/', '_').replace('(', '').replace(')', '')


def send_chunk(producer, chunk: pd.DataFrame, bulk_mode: bool, filename: str = '') -> int:
    """Clean, transform, and send a DataFrame chunk to Kafka. Returns rows sent."""
    chunk = clean_dataframe(chunk, filename=filename)
    chunk.columns = [safe_col_name(c) for c in chunk.columns]

    if 'Timestamp' not in chunk.columns:
        logger.warning("No Timestamp column after cleaning — skipping chunk")
        return 0

    chunk = chunk.sort_values('Timestamp')

    sent = 0
    prev_ts = None
    for row in chunk.itertuples(index=False):
        msg = row_to_message(row)
        producer.send(TOPIC, value=msg)
        sent += 1

        if not bulk_mode:
            curr_ts = getattr(row, 'Timestamp', None)
            if prev_ts is not None and curr_ts is not None:
                try:
                    delay = (curr_ts - prev_ts).total_seconds() / REPLAY_SPEED
                    if 0 < delay < 1:
                        time.sleep(delay)
                except Exception:
                    pass
            prev_ts = curr_ts

    return sent


def main():
    wait_for_kafka(KAFKA_BOOTSTRAP)

    producer = KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP,
        value_serializer=lambda v: json.dumps(v, default=str).encode('utf-8'),
        batch_size=32768,
        linger_ms=20,
        buffer_memory=67108864,
        acks=1,
    )

    total_sent = 0
    start_time = time.time()

    for csv_file in CSV_FILES:
        filepath = os.path.join(DATA_DIR, csv_file)
        if not os.path.exists(filepath):
            logger.warning("File not found, skipping: %s", filepath)
            continue

        logger.info("Processing %s in chunks of %d ...", csv_file, CHUNK_SIZE)
        file_sent = 0

        try:
            reader = pd.read_csv(
                filepath,
                encoding='utf-8',
                low_memory=False,
                chunksize=CHUNK_SIZE,
                on_bad_lines='skip',
            )
            for chunk_num, chunk in enumerate(reader):
                sent = send_chunk(producer, chunk, BULK_MODE, filename=csv_file)
                file_sent += sent
                total_sent += sent
                logger.info("  %s chunk %d — %d sent (file: %d, total: %d)",
                            csv_file, chunk_num + 1, sent, file_sent, total_sent)
                producer.flush()
        except Exception as e:
            logger.error("Error processing %s: %s", csv_file, e, exc_info=True)
            continue

        producer.flush()
        logger.info("Completed %s — %d records (total: %d)", csv_file, file_sent, total_sent)

    producer.send(TOPIC, value={
        '_sentinel': 'END_OF_STREAM',
        'total_records': total_sent,
    })
    producer.flush()
    producer.close()

    elapsed = time.time() - start_time
    logger.info("Producer finished: %d records in %.1f seconds (%.0f records/sec)",
                total_sent, elapsed, total_sent / max(elapsed, 1))


if __name__ == '__main__':
    main()
