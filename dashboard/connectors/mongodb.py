"""
CyberSight DW — MongoDB Dashboard Connector
Implements all supported queries using MongoDB aggregation pipelines.
Uses attack_hourly_summary where possible to avoid full collection scans.
"""

import os
import logging
from datetime import datetime, timedelta

import pandas as pd
from pymongo import MongoClient

logger = logging.getLogger(__name__)

MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://mongodb:27017')
MONGO_DB = 'cybersight'


class MongoDBConnector:
    def __init__(self):
        self.client = MongoClient(MONGO_URI)
        self.db = self.client[MONGO_DB]

    def _agg(self, collection: str, pipeline: list) -> pd.DataFrame:
        result = list(self.db[collection].aggregate(pipeline, allowDiskUse=True))
        if not result:
            return pd.DataFrame()
        return pd.DataFrame(result)

    # -----------------------------------------------------------------
    # Q1: Attack count by category (uses summary)
    # -----------------------------------------------------------------
    def q1_attack_counts(self) -> pd.DataFrame:
        pipeline = [
            {'$match': {'attack_category': {'$ne': 'Normal'}}},
            {'$group': {'_id': '$attack_category', 'total_events': {'$sum': '$event_count'}}},
            {'$sort': {'total_events': -1}},
            {'$project': {'_id': 0, 'attack_category': '$_id', 'total_events': 1}},
        ]
        return self._agg('attack_hourly_summary', pipeline)

    # -----------------------------------------------------------------
    # Q2: Hourly attack trend (uses summary)
    # -----------------------------------------------------------------
    def q2_hourly_trend(self, target_date: str = None) -> pd.DataFrame:
        match = {'attack_category': {'$ne': 'Normal'}}
        if target_date:
            dt = datetime.strptime(target_date, '%Y-%m-%d')
            match['hour_bucket'] = {
                '$gte': dt,
                '$lt': dt + timedelta(days=1),
            }
        pipeline = [
            {'$match': match},
            {'$group': {
                '_id': {'hour_bucket': '$hour_bucket', 'attack_category': '$attack_category'},
                'event_count': {'$sum': '$event_count'},
            }},
            {'$sort': {'_id.hour_bucket': 1}},
            {'$project': {
                '_id': 0,
                'hour_bucket': '$_id.hour_bucket',
                'attack_category': '$_id.attack_category',
                'event_count': 1,
            }},
        ]
        return self._agg('attack_hourly_summary', pipeline)

    # -----------------------------------------------------------------
    # Q3: Top 10 source IPs (network_events — no summary alternative)
    # -----------------------------------------------------------------
    def q3_top_sources(self) -> pd.DataFrame:
        pipeline = [
            {'$match': {'attack.is_attack': True}},
            {'$group': {
                '_id': '$source.ip',
                'total_attacks': {'$sum': 1},
                'country': {'$first': '$source.country'},
            }},
            {'$sort': {'total_attacks': -1}},
            {'$limit': 10},
            {'$project': {
                '_id': 0, 'source_ip': '$_id',
                'country': 1, 'total_attacks': 1,
            }},
        ]
        return self._agg('network_events', pipeline)

    # -----------------------------------------------------------------
    # Q4: Attack type distribution (uses summary)
    # -----------------------------------------------------------------
    def q4_attack_distribution(self) -> pd.DataFrame:
        pipeline = [
            {'$group': {
                '_id': '$attack_category',
                'event_count': {'$sum': '$event_count'},
            }},
            {'$sort': {'event_count': -1}},
            {'$project': {'_id': 0, 'attack_category': '$_id', 'event_count': 1}},
        ]
        return self._agg('attack_hourly_summary', pipeline)

    # -----------------------------------------------------------------
    # Q5: Protocol usage breakdown (network_events)
    # -----------------------------------------------------------------
    def q5_protocol_breakdown(self) -> pd.DataFrame:
        pipeline = [
            {'$group': {
                '_id': '$protocol.name',
                'total_events': {'$sum': 1},
                'attack_events': {
                    '$sum': {'$cond': ['$attack.is_attack', 1, 0]}
                },
            }},
            {'$addFields': {
                'attack_pct': {
                    '$round': [
                        {'$multiply': [
                            {'$divide': ['$attack_events', {'$max': ['$total_events', 1]}]},
                            100
                        ]}, 2
                    ]
                }
            }},
            {'$sort': {'total_events': -1}},
            {'$project': {
                '_id': 0, 'protocol_name': '$_id',
                'total_events': 1, 'attack_events': 1, 'attack_pct': 1,
            }},
        ]
        return self._agg('network_events', pipeline)

    # -----------------------------------------------------------------
    # Q6: Most targeted destination ports
    # -----------------------------------------------------------------
    def q6_targeted_ports(self) -> pd.DataFrame:
        pipeline = [
            {'$match': {'attack.is_attack': True}},
            {'$group': {
                '_id': {'port': '$destination.port', 'service': '$destination.service_name'},
                'attack_count': {'$sum': 1},
            }},
            {'$sort': {'attack_count': -1}},
            {'$limit': 15},
            {'$project': {
                '_id': 0,
                'dest_port': '$_id.port',
                'service_name': '$_id.service',
                'attack_count': 1,
            }},
        ]
        return self._agg('network_events', pipeline)

    # -----------------------------------------------------------------
    # Q7: Average flow duration by attack type
    # -----------------------------------------------------------------
    def q7_avg_duration(self) -> pd.DataFrame:
        pipeline = [
            {'$match': {'attack.is_attack': True}},
            {'$group': {
                '_id': {'label': '$attack.label', 'category': '$attack.category'},
                'event_count': {'$sum': 1},
                'avg_duration_ms': {'$avg': {'$divide': ['$metrics.flow_duration', 1000]}},
                'avg_total_bytes': {
                    '$avg': {'$add': ['$metrics.fwd_bytes', '$metrics.bwd_bytes']}
                },
            }},
            {'$sort': {'avg_duration_ms': -1}},
            {'$project': {
                '_id': 0,
                'attack_label': '$_id.label',
                'attack_category': '$_id.category',
                'event_count': 1,
                'avg_duration_ms': {'$round': ['$avg_duration_ms', 2]},
                'avg_total_bytes': {'$round': ['$avg_total_bytes', 2]},
            }},
        ]
        return self._agg('network_events', pipeline)

    # -----------------------------------------------------------------
    # Q9: Country-level threat summary
    # -----------------------------------------------------------------
    def q9_country_summary(self) -> pd.DataFrame:
        pipeline = [
            {'$group': {
                '_id': '$source.country',
                'total_events': {'$sum': 1},
                'attack_events': {
                    '$sum': {'$cond': ['$attack.is_attack', 1, 0]}
                },
                'unique_ips': {'$addToSet': '$source.ip'},
            }},
            {'$addFields': {
                'unique_ips': {'$size': '$unique_ips'},
                'attack_rate_pct': {
                    '$round': [
                        {'$multiply': [
                            {'$divide': ['$attack_events', {'$max': ['$total_events', 1]}]},
                            100
                        ]}, 2
                    ]
                }
            }},
            {'$sort': {'attack_events': -1}},
            {'$project': {
                '_id': 0, 'country': '$_id',
                'total_events': 1, 'attack_events': 1,
                'unique_ips': 1, 'attack_rate_pct': 1,
            }},
        ]
        return self._agg('network_events', pipeline)

    # -----------------------------------------------------------------
    # Q10: Severity over time
    # -----------------------------------------------------------------
    def q10_severity_over_time(self) -> pd.DataFrame:
        pipeline = [
            {'$match': {'attack.is_attack': True}},
            {'$group': {
                '_id': {
                    'day': {'$dateToString': {'format': '%Y-%m-%d', 'date': '$timestamp'}},
                    'severity': '$attack.severity',
                },
                'event_count': {'$sum': 1},
            }},
            {'$sort': {'_id.day': 1}},
            {'$project': {
                '_id': 0,
                'day': '$_id.day',
                'severity': '$_id.severity',
                'event_count': 1,
            }},
        ]
        return self._agg('network_events', pipeline)

    # -----------------------------------------------------------------
    # Q11: Weekend vs weekday comparison
    # -----------------------------------------------------------------
    def q11_weekend_weekday(self) -> pd.DataFrame:
        pipeline = [
            {'$group': {
                '_id': {
                    'is_weekend': '$time.is_weekend',
                    'attack_category': '$attack.category',
                },
                'total_events': {'$sum': 1},
                'attack_events': {
                    '$sum': {'$cond': ['$attack.is_attack', 1, 0]}
                },
            }},
            {'$addFields': {
                'attack_rate_pct': {
                    '$round': [
                        {'$multiply': [
                            {'$divide': ['$attack_events', {'$max': ['$total_events', 1]}]},
                            100
                        ]}, 2
                    ]
                }
            }},
            {'$sort': {'_id.is_weekend': 1, 'attack_events': -1}},
            {'$project': {
                '_id': 0,
                'is_weekend': '$_id.is_weekend',
                'attack_category': '$_id.attack_category',
                'total_events': 1,
                'attack_events': 1,
                'attack_rate_pct': 1,
            }},
        ]
        return self._agg('network_events', pipeline)

    # -----------------------------------------------------------------
    # Q12: Botnet activity timeline
    # -----------------------------------------------------------------
    def q12_botnet_timeline(self) -> pd.DataFrame:
        pipeline = [
            {'$match': {'attack_category': 'Botnet'}},
            {'$group': {
                '_id': '$hour_bucket',
                'bot_events': {'$sum': '$event_count'},
                'total_bytes': {'$sum': '$total_bytes'},
            }},
            {'$sort': {'_id': 1}},
            {'$project': {
                '_id': 0, 'hour_bucket': '$_id',
                'bot_events': 1, 'total_bytes': 1,
            }},
        ]
        return self._agg('attack_hourly_summary', pipeline)

    # -----------------------------------------------------------------
    # Utility
    # -----------------------------------------------------------------
    def get_record_count(self) -> int:
        return self.db['network_events'].estimated_document_count()
