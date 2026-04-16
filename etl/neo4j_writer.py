"""
CyberSight DW — Neo4j Writer
Incrementally builds the Neo4j graph from raw Kafka event batches.
All relationships are aggregated using MERGE with ON CREATE / ON MATCH.
Uses UNWIND with batched parameter lists.
"""

import logging
import time
from collections import defaultdict
from datetime import datetime

from neo4j import GraphDatabase

from mappings import SERVICE_MAP, TRANSPORT_LAYER_MAP

logger = logging.getLogger('neo4j_writer')

NEO4J_BATCH_SIZE = 500


class Neo4jWriter:
    def __init__(self, uri: str, user: str, password: str):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self._wait_for_neo4j()
        self._ensure_constraints()

    def _wait_for_neo4j(self, retries=20, delay=5):
        for attempt in range(retries):
            try:
                with self.driver.session() as s:
                    s.run("RETURN 1")
                logger.info("Neo4j is ready")
                return
            except Exception:
                logger.warning("Neo4j not ready (attempt %d/%d)", attempt + 1, retries)
                time.sleep(delay)
        raise ConnectionError("Neo4j not reachable after retries")

    def _ensure_constraints(self):
        constraints = [
            "CREATE CONSTRAINT source_ip_unique IF NOT EXISTS FOR (n:SourceIP) REQUIRE n.ip IS UNIQUE",
            "CREATE CONSTRAINT dest_ip_unique IF NOT EXISTS FOR (n:DestinationIP) REQUIRE n.ip IS UNIQUE",
            "CREATE CONSTRAINT attack_label_unique IF NOT EXISTS FOR (n:AttackType) REQUIRE n.label IS UNIQUE",
            "CREATE CONSTRAINT protocol_unique IF NOT EXISTS FOR (n:Protocol) REQUIRE n.name IS UNIQUE",
            "CREATE CONSTRAINT timewindow_unique IF NOT EXISTS FOR (n:TimeWindow) REQUIRE n.hour_bucket IS UNIQUE",
        ]
        with self.driver.session() as session:
            for cypher in constraints:
                try:
                    session.run(cypher)
                except Exception as e:
                    logger.debug("Constraint may exist: %s", e)
        logger.info("Neo4j constraints ensured")

    def write_batch(self, events: list[dict]):
        """
        Aggregate a batch of raw Kafka events in Python,
        then write aggregated data to Neo4j using MERGE + UNWIND.
        """
        attacked = defaultdict(lambda: {'cnt': 0, 'total_bytes': 0, 'first_seen': '', 'last_seen': ''})
        used_attack = defaultdict(lambda: {'cnt': 0, 'first_seen': '', 'last_seen': ''})
        targeted_by = defaultdict(lambda: {'cnt': 0})
        used_protocol = defaultdict(lambda: {'cnt': 0})
        active_in = defaultdict(lambda: {'event_count': 0})

        for e in events:
            src_ip = e.get('source_ip', '0.0.0.0')
            dst_ip = e.get('destination_ip', '0.0.0.0')
            label = e.get('label', 'BENIGN')
            category = e.get('attack_category', 'Normal')
            severity = e.get('severity', 'LOW')
            protocol = e.get('protocol', 'OTHER')
            ts_str = e.get('timestamp', '')
            country = e.get('source_country', 'Unknown')
            region = e.get('source_region', 'Unknown')
            dest_port = int(e.get('destination_port', 0))
            svc = SERVICE_MAP.get(dest_port, ('Unknown', 'Unknown'))

            fwd_bytes = int(e.get('fwd_bytes', 0))
            bwd_bytes = int(e.get('bwd_bytes', 0))
            total_bytes = fwd_bytes + bwd_bytes

            try:
                ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
            except Exception:
                try:
                    ts = datetime.strptime(ts_str[:19], '%Y-%m-%dT%H:%M:%S')
                except Exception:
                    ts = datetime.now()

            ts_iso = ts_str if ts_str else ts.isoformat()
            hour_bucket = ts.strftime('%Y-%m-%dT%H:00:00')
            # ATTACKED: (src_ip, dst_ip, country, region, svc_name, svc_type)
            akey = (src_ip, dst_ip, country, region, svc[0], svc[1])
            a = attacked[akey]
            a['cnt'] += 1
            a['total_bytes'] += total_bytes
            if not a['first_seen'] or ts_iso < a['first_seen']:
                a['first_seen'] = ts_iso
            if not a['last_seen'] or ts_iso > a['last_seen']:
                a['last_seen'] = ts_iso

            # USED_ATTACK: (src_ip, country, region, label, category, severity)
            ukey = (src_ip, country, region, label, category, severity)
            u = used_attack[ukey]
            u['cnt'] += 1
            if not u['first_seen'] or ts_iso < u['first_seen']:
                u['first_seen'] = ts_iso
            if not u['last_seen'] or ts_iso > u['last_seen']:
                u['last_seen'] = ts_iso
            # TARGETED_BY: (dst_ip, svc_name, svc_type, label, category, severity)
            tkey = (dst_ip, svc[0], svc[1], label, category, severity)
            targeted_by[tkey]['cnt'] += 1

            # USED_PROTOCOL: (src_ip, protocol)
            used_protocol[(src_ip, protocol)]['cnt'] += 1

            # ACTIVE_IN: (label, category, severity, hour_bucket, day, month, year)
            transport = TRANSPORT_LAYER_MAP.get(protocol, 'Unknown')
            day_of_week = ts.weekday()
            aikey = (label, category, severity, hour_bucket, day_of_week, ts.month, ts.year)
            active_in[aikey]['event_count'] += 1

        self._write_attacked(attacked)
        self._write_used_attack(used_attack)
        self._write_targeted_by(targeted_by)
        self._write_used_protocol(used_protocol)
        self._write_active_in(active_in)

    def _write_attacked(self, agg: dict):
        batch = []
        for (src_ip, dst_ip, country, region, svc_name, svc_type), vals in agg.items():
            batch.append({
                'src_ip': src_ip, 'dst_ip': dst_ip,
                'country': country, 'region': region,
                'service_name': svc_name, 'service_type': svc_type,
                'cnt': vals['cnt'], 'total_bytes': vals['total_bytes'],
                'first_seen': vals['first_seen'], 'last_seen': vals['last_seen'],
            })
            if len(batch) >= NEO4J_BATCH_SIZE:
                self._run_attacked(batch)
                batch = []
        if batch:
            self._run_attacked(batch)

    def _run_attacked(self, batch):
        with self.driver.session() as session:
            session.run("""
                UNWIND $batch AS row
                MERGE (s:SourceIP {ip: row.src_ip})
                  ON CREATE SET s.country = row.country, s.region = row.region
                MERGE (d:DestinationIP {ip: row.dst_ip})
                  ON CREATE SET d.service_name = row.service_name, d.service_type = row.service_type
                MERGE (s)-[r:ATTACKED]->(d)
                  ON CREATE SET r.count = row.cnt, r.total_bytes = row.total_bytes,
                                r.first_seen = row.first_seen, r.last_seen = row.last_seen
                  ON MATCH SET  r.count = r.count + row.cnt,
                                r.total_bytes = r.total_bytes + row.total_bytes,
                                r.last_seen = row.last_seen
            """, batch=batch)

    def _write_used_attack(self, agg: dict):
        batch = []
        for (src_ip, country, region, label, category, severity), vals in agg.items():
            batch.append({
                'src_ip': src_ip, 'country': country, 'region': region,
                'label': label, 'category': category, 'severity': severity,
                'cnt': vals['cnt'],
                'first_seen': vals['first_seen'], 'last_seen': vals['last_seen'],
            })
            if len(batch) >= NEO4J_BATCH_SIZE:
                self._run_used_attack(batch)
                batch = []
        if batch:
            self._run_used_attack(batch)

    def _run_used_attack(self, batch):
        with self.driver.session() as session:
            session.run("""
                UNWIND $batch AS row
                MERGE (s:SourceIP {ip: row.src_ip})
                  ON CREATE SET s.country = row.country, s.region = row.region
                MERGE (a:AttackType {label: row.label})
                  ON CREATE SET a.category = row.category, a.severity = row.severity
                MERGE (s)-[r:USED_ATTACK]->(a)
                  ON CREATE SET r.count = row.cnt,
                                r.first_seen = row.first_seen, r.last_seen = row.last_seen
                  ON MATCH SET  r.count = r.count + row.cnt, r.last_seen = row.last_seen
            """, batch=batch)

    def _write_targeted_by(self, agg: dict):
        batch = []
        for (dst_ip, svc_name, svc_type, label, category, severity), vals in agg.items():
            batch.append({
                'dst_ip': dst_ip, 'service_name': svc_name, 'service_type': svc_type,
                'label': label, 'category': category, 'severity': severity,
                'cnt': vals['cnt'],
            })
            if len(batch) >= NEO4J_BATCH_SIZE:
                self._run_targeted_by(batch)
                batch = []
        if batch:
            self._run_targeted_by(batch)

    def _run_targeted_by(self, batch):
        with self.driver.session() as session:
            session.run("""
                UNWIND $batch AS row
                MERGE (d:DestinationIP {ip: row.dst_ip})
                  ON CREATE SET d.service_name = row.service_name, d.service_type = row.service_type
                MERGE (a:AttackType {label: row.label})
                  ON CREATE SET a.category = row.category, a.severity = row.severity
                MERGE (d)-[r:TARGETED_BY]->(a)
                  ON CREATE SET r.count = row.cnt
                  ON MATCH SET  r.count = r.count + row.cnt
            """, batch=batch)

    def _write_used_protocol(self, agg: dict):
        batch = []
        for (src_ip, protocol), vals in agg.items():
            batch.append({
                'src_ip': src_ip, 'protocol': protocol,
                'transport': TRANSPORT_LAYER_MAP.get(protocol, 'Unknown'),
                'cnt': vals['cnt'],
            })
            if len(batch) >= NEO4J_BATCH_SIZE:
                self._run_used_protocol(batch)
                batch = []
        if batch:
            self._run_used_protocol(batch)

    def _run_used_protocol(self, batch):
        with self.driver.session() as session:
            session.run("""
                UNWIND $batch AS row
                MERGE (s:SourceIP {ip: row.src_ip})
                MERGE (p:Protocol {name: row.protocol})
                  ON CREATE SET p.transport_layer = row.transport
                MERGE (s)-[r:USED_PROTOCOL]->(p)
                  ON CREATE SET r.count = row.cnt
                  ON MATCH SET  r.count = r.count + row.cnt
            """, batch=batch)

    def _write_active_in(self, agg: dict):
        batch = []
        for (label, category, severity, hour_bucket, day, month, year), vals in agg.items():
            batch.append({
                'label': label, 'category': category, 'severity': severity,
                'hour_bucket': hour_bucket, 'day': day, 'month': month, 'year': year,
                'event_count': vals['event_count'],
            })
            if len(batch) >= NEO4J_BATCH_SIZE:
                self._run_active_in(batch)
                batch = []
        if batch:
            self._run_active_in(batch)

    def _run_active_in(self, batch):
        with self.driver.session() as session:
            session.run("""
                UNWIND $batch AS row
                MERGE (a:AttackType {label: row.label})
                  ON CREATE SET a.category = row.category, a.severity = row.severity
                MERGE (t:TimeWindow {hour_bucket: row.hour_bucket})
                  ON CREATE SET t.day_of_week = row.day, t.month = row.month, t.year = row.year
                MERGE (a)-[r:ACTIVE_IN]->(t)
                  ON CREATE SET r.event_count = row.event_count
                  ON MATCH SET  r.event_count = r.event_count + row.event_count
            """, batch=batch)

    def compute_co_attackers(self):
        """Post-load step: find SourceIP pairs sharing the same AttackType."""
        logger.info("Computing CONNECTED_TO (co-attacker) relationships...")
        with self.driver.session() as session:
            session.run("""
                MATCH (s1:SourceIP)-[:USED_ATTACK]->(a:AttackType)<-[:USED_ATTACK]-(s2:SourceIP)
                WHERE s1.ip < s2.ip
                WITH s1, s2, COLLECT(DISTINCT a.label) AS shared_attacks, COUNT(DISTINCT a) AS shared_count
                MERGE (s1)-[r:CONNECTED_TO]-(s2)
                ON CREATE SET r.shared_attacks = shared_attacks, r.shared_count = shared_count
                ON MATCH SET r.shared_attacks = shared_attacks, r.shared_count = shared_count
            """)
        logger.info("CONNECTED_TO relationships created")

    def get_node_count(self) -> int:
        with self.driver.session() as session:
            result = session.run("MATCH (n) RETURN COUNT(n) AS cnt")
            record = result.single()
            return record['cnt'] if record else 0

    def close(self):
        self.driver.close()
