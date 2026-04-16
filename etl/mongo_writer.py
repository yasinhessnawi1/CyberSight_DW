"""
CyberSight DW — MongoDB Writer
Transforms raw Kafka event dicts into embedded MongoDB documents
and bulk-inserts them. Used by the consumer for real-time writes.
"""

import logging
from datetime import datetime
from collections import defaultdict

from pymongo import MongoClient, ASCENDING, UpdateOne
from pymongo.errors import BulkWriteError

from mappings import (
    SERVICE_MAP, TRANSPORT_LAYER_MAP, DAY_NAMES, time_of_day,
)

logger = logging.getLogger('mongo_writer')


def event_to_document(event: dict) -> dict:
    """Transform a raw Kafka event dict into the MongoDB embedded document schema."""
    ts_str = event.get('timestamp', '')
    try:
        ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
    except (ValueError, AttributeError):
        try:
            ts = datetime.strptime(ts_str[:19], '%Y-%m-%dT%H:%M:%S')
        except Exception:
            ts = datetime.now()

    iso_cal = ts.isocalendar()
    dest_port = int(event.get('destination_port', 0))
    svc = SERVICE_MAP.get(dest_port, ('Unknown', 'Unknown'))
    protocol = event.get('protocol', 'OTHER')
    category = event.get('attack_category', 'Normal')

    return {
        'timestamp': ts,
        'time': {
            'hour': ts.hour,
            'day': ts.day,
            'week': iso_cal[1],
            'month': ts.month,
            'year': ts.year,
            'day_of_week': DAY_NAMES[ts.weekday()],
            'is_weekend': ts.weekday() >= 5,
            'time_of_day': time_of_day(ts.hour),
        },
        'source': {
            'ip': event.get('source_ip', '0.0.0.0'),
            'port': int(event.get('source_port', 0)),
            'country': event.get('source_country', 'Unknown'),
            'region': event.get('source_region', 'Unknown'),
        },
        'destination': {
            'ip': event.get('destination_ip', '0.0.0.0'),
            'port': dest_port,
            'service_name': svc[0],
            'service_type': svc[1],
        },
        'attack': {
            'label': event.get('label', 'BENIGN'),
            'category': category,
            'severity': event.get('severity', 'LOW'),
            'is_attack': category != 'Normal',
        },
        'protocol': {
            'name': protocol,
            'transport_layer': TRANSPORT_LAYER_MAP.get(protocol, 'Unknown'),
        },
        'metrics': {
            'flow_duration': int(event.get('flow_duration', 0)),
            'fwd_packets': int(event.get('fwd_packets', 0)),
            'bwd_packets': int(event.get('bwd_packets', 0)),
            'fwd_bytes': int(event.get('fwd_bytes', 0)),
            'bwd_bytes': int(event.get('bwd_bytes', 0)),
            'flow_bytes_per_sec': float(event.get('flow_bytes_per_sec', 0)),
            'flow_pkts_per_sec': float(event.get('flow_packets_per_sec', 0)),
        },
    }


class MongoWriter:
    def __init__(self, mongo_uri: str, db_name: str = 'cybersight'):
        self.client = MongoClient(mongo_uri)
        self.db = self.client[db_name]
        self._ensure_indexes()

    def _ensure_indexes(self):
        coll = self.db['network_events']
        coll.create_index([('timestamp', ASCENDING)])
        coll.create_index([('attack.category', ASCENDING)])
        coll.create_index([('attack.is_attack', ASCENDING)])
        coll.create_index([('source.ip', ASCENDING)])
        coll.create_index([('attack.category', ASCENDING), ('timestamp', ASCENDING)])

        summary = self.db['attack_hourly_summary']
        summary.create_index(
            [('hour_bucket', ASCENDING), ('attack_label', ASCENDING)],
            unique=True
        )
        logger.info("MongoDB indexes ensured")

    def write_batch(self, events: list[dict]):
        """Transform and insert a batch of raw Kafka events into MongoDB,
        then incrementally update the attack_hourly_summary collection."""
        docs = [event_to_document(e) for e in events]
        if not docs:
            return
        try:
            self.db['network_events'].insert_many(docs, ordered=False)
        except BulkWriteError as e:
            logger.warning("MongoDB bulk write: %d errors",
                           len(e.details.get('writeErrors', [])))

        self._update_hourly_summary(docs)

    def _update_hourly_summary(self, docs: list[dict]):
        """Aggregate the batch by (hour_bucket, attack_label, attack_category)
        and upsert into attack_hourly_summary."""
        agg = defaultdict(lambda: {'event_count': 0, 'total_bytes': 0,
                                    'duration_sum': 0.0, 'sources': set()})
        for doc in docs:
            ts = doc['timestamp']
            hour_bucket = ts.replace(minute=0, second=0, microsecond=0)
            label = doc['attack']['label']
            category = doc['attack']['category']
            severity = doc['attack']['severity']

            key = (hour_bucket, label, category, severity)
            a = agg[key]
            a['event_count'] += 1
            a['total_bytes'] += doc['metrics'].get('fwd_bytes', 0) + doc['metrics'].get('bwd_bytes', 0)
            a['duration_sum'] += doc['metrics'].get('flow_duration', 0) / 1000.0
            a['sources'].add(doc['source']['ip'])

        ops = []
        for (hour_bucket, label, category, severity), vals in agg.items():
            ops.append(UpdateOne(
                {'hour_bucket': hour_bucket, 'attack_label': label},
                {
                    '$inc': {
                        'event_count': vals['event_count'],
                        'total_bytes': vals['total_bytes'],
                    },
                    '$set': {
                        'attack_category': category,
                        'severity': severity,
                    },
                    '$setOnInsert': {
                        'hour_bucket': hour_bucket,
                        'attack_label': label,
                    },
                },
                upsert=True,
            ))

        if ops:
            try:
                self.db['attack_hourly_summary'].bulk_write(ops, ordered=False)
            except Exception as e:
                logger.warning("MongoDB summary update error: %s", e)

    def get_count(self) -> int:
        return self.db['network_events'].estimated_document_count()

    def close(self):
        self.client.close()
