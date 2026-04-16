"""
CyberSight DW — Neo4j Dashboard Connector
Implements supported queries using Cypher.
Uses context manager pattern to properly close sessions.
"""

import os
import logging

import pandas as pd
from neo4j import GraphDatabase

logger = logging.getLogger(__name__)

NEO4J_URI = os.environ.get('NEO4J_URI', 'bolt://neo4j:7687')
NEO4J_USER = os.environ.get('NEO4J_USER', 'neo4j')
NEO4J_PASSWORD = os.environ.get('NEO4J_PASSWORD', 'password')


class Neo4jConnector:
    def __init__(self):
        self.driver = GraphDatabase.driver(
            NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD)
        )

    def _query(self, cypher: str, **params) -> pd.DataFrame:
        with self.driver.session() as session:
            result = session.run(cypher, **params)
            records = [record.data() for record in result]
        if not records:
            return pd.DataFrame()
        return pd.DataFrame(records)

    # -----------------------------------------------------------------
    # Q1: Attack count by category
    # -----------------------------------------------------------------
    def q1_attack_counts(self) -> pd.DataFrame:
        return self._query("""
            MATCH (s:SourceIP)-[r:USED_ATTACK]->(a:AttackType)
            WHERE a.category <> 'Normal'
            RETURN a.category AS attack_category, SUM(r.count) AS total_events
            ORDER BY total_events DESC
        """)

    # -----------------------------------------------------------------
    # Q2: Hourly attack trend
    # -----------------------------------------------------------------
    def q2_hourly_trend(self, target_date: str = None) -> pd.DataFrame:
        if target_date:
            return self._query("""
                MATCH (a:AttackType)-[r:ACTIVE_IN]->(t:TimeWindow)
                WHERE a.category <> 'Normal' AND t.hour_bucket STARTS WITH $prefix
                RETURN t.hour_bucket AS hour_bucket, a.category AS attack_category,
                       r.event_count AS event_count
                ORDER BY t.hour_bucket
            """, prefix=target_date)
        return self._query("""
            MATCH (a:AttackType)-[r:ACTIVE_IN]->(t:TimeWindow)
            WHERE a.category <> 'Normal'
            RETURN t.hour_bucket AS hour_bucket, a.category AS attack_category,
                   r.event_count AS event_count
            ORDER BY t.hour_bucket
        """)

    # -----------------------------------------------------------------
    # Q3: Top 10 source IPs
    # -----------------------------------------------------------------
    def q3_top_sources(self) -> pd.DataFrame:
        return self._query("""
            MATCH (s:SourceIP)-[r:USED_ATTACK]->(a:AttackType)
            WHERE a.category <> 'Normal'
            RETURN s.ip AS source_ip, s.country AS country,
                   SUM(r.count) AS total_attacks
            ORDER BY total_attacks DESC
            LIMIT 10
        """)

    # -----------------------------------------------------------------
    # Q4: Attack type distribution
    # -----------------------------------------------------------------
    def q4_attack_distribution(self) -> pd.DataFrame:
        return self._query("""
            MATCH (s:SourceIP)-[r:USED_ATTACK]->(a:AttackType)
            WITH a.category AS attack_category, SUM(r.count) AS event_count
            RETURN attack_category, event_count
            ORDER BY event_count DESC
        """)

    # -----------------------------------------------------------------
    # Q5: Protocol usage breakdown
    # -----------------------------------------------------------------
    def q5_protocol_breakdown(self) -> pd.DataFrame:
        return self._query("""
            MATCH (s:SourceIP)-[r:USED_PROTOCOL]->(p:Protocol)
            RETURN p.name AS protocol_name, SUM(r.count) AS total_events
            ORDER BY total_events DESC
        """)

    # -----------------------------------------------------------------
    # Q6: Most targeted destination ports
    # -----------------------------------------------------------------
    def q6_targeted_ports(self) -> pd.DataFrame:
        return self._query("""
            MATCH (d:DestinationIP)<-[r:ATTACKED]-(s:SourceIP)
            RETURN d.ip AS dest_ip, d.service_name AS service_name,
                   SUM(r.count) AS attack_count
            ORDER BY attack_count DESC
            LIMIT 15
        """)

    # -----------------------------------------------------------------
    # Q7: Attack event counts by type (Neo4j graph lacks per-flow duration;
    #     returns event_count with avg_duration_ms=0 for column compatibility)
    # -----------------------------------------------------------------
    def q7_avg_duration(self) -> pd.DataFrame:
        return self._query("""
            MATCH (a:AttackType)-[r:ACTIVE_IN]->(t:TimeWindow)
            WHERE a.category <> 'Normal'
            RETURN a.label AS attack_label, a.category AS attack_category,
                   SUM(r.event_count) AS event_count, 0 AS avg_duration_ms
            ORDER BY event_count DESC
        """)

    # -----------------------------------------------------------------
    # Q8: Co-attacking IPs (Neo4j only)
    # -----------------------------------------------------------------
    def q8_co_attackers(self) -> pd.DataFrame:
        return self._query("""
            MATCH (s1:SourceIP)-[r:CONNECTED_TO]-(s2:SourceIP)
            WHERE s1.ip < s2.ip
            RETURN s1.ip AS ip1, s1.country AS country1,
                   s2.ip AS ip2, s2.country AS country2,
                   r.shared_attacks AS shared_attacks,
                   r.shared_count AS shared_count
            ORDER BY r.shared_count DESC
            LIMIT 20
        """)

    # -----------------------------------------------------------------
    # Q9: Country-level threat summary
    # -----------------------------------------------------------------
    def q9_country_summary(self) -> pd.DataFrame:
        return self._query("""
            MATCH (s:SourceIP)-[r:USED_ATTACK]->(a:AttackType)
            WHERE a.category <> 'Normal'
            WITH s.country AS country, SUM(r.count) AS attack_events,
                 COUNT(DISTINCT s) AS unique_ips
            RETURN country, attack_events, unique_ips
            ORDER BY attack_events DESC
        """)

    # -----------------------------------------------------------------
    # Q10: Attack severity over time
    # -----------------------------------------------------------------
    def q10_severity_over_time(self) -> pd.DataFrame:
        return self._query("""
            MATCH (a:AttackType)-[r:ACTIVE_IN]->(t:TimeWindow)
            WHERE a.category <> 'Normal'
            RETURN t.hour_bucket AS hour_bucket, a.severity AS severity,
                   r.event_count AS event_count
            ORDER BY t.hour_bucket
        """)

    # -----------------------------------------------------------------
    # Q11: Weekend vs weekday (via TimeWindow day property)
    # -----------------------------------------------------------------
    def q11_weekend_weekday(self) -> pd.DataFrame:
        return self._query("""
            MATCH (a:AttackType)-[r:ACTIVE_IN]->(t:TimeWindow)
            WITH a, r, t,
                 CASE WHEN t.day_of_week IN [5, 6] THEN true ELSE false END AS is_weekend
            RETURN is_weekend, a.category AS attack_category,
                   SUM(r.event_count) AS attack_events
            ORDER BY is_weekend, attack_events DESC
        """)

    # -----------------------------------------------------------------
    # Q12: Botnet activity timeline
    # -----------------------------------------------------------------
    def q12_botnet_timeline(self) -> pd.DataFrame:
        return self._query("""
            MATCH (a:AttackType {category: 'Botnet'})-[r:ACTIVE_IN]->(t:TimeWindow)
            RETURN t.hour_bucket AS hour_bucket, r.event_count AS bot_events
            ORDER BY t.hour_bucket
        """)

    # -----------------------------------------------------------------
    # Utility
    # -----------------------------------------------------------------
    def get_node_count(self) -> int:
        df = self._query("MATCH (n) RETURN COUNT(n) AS cnt")
        return int(df.iloc[0]['cnt']) if not df.empty else 0

    def get_relationship_count(self) -> int:
        df = self._query("MATCH ()-[r]->() RETURN COUNT(r) AS cnt")
        return int(df.iloc[0]['cnt']) if not df.empty else 0

    def get_top_attacked_destinations(self) -> pd.DataFrame:
        return self._query("""
            MATCH (d:DestinationIP)<-[r:ATTACKED]-(s:SourceIP)
            RETURN d.ip AS dest_ip, d.service_name AS service_name,
                   SUM(r.count) AS hit_count
            ORDER BY hit_count DESC
            LIMIT 10
        """)

    def close(self):
        self.driver.close()
