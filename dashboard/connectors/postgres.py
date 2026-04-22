"""
CyberSight DW — PostgreSQL Dashboard Connector
Uses summary tables for all dashboard queries to avoid full fact-table scans.
Connection pooling via psycopg2.pool for efficiency.
"""

import os
import logging

import pandas as pd
import psycopg2
import psycopg2.pool
import psycopg2.extras

logger = logging.getLogger(__name__)

PG_HOST = os.environ.get('PG_HOST', 'postgres')
PG_PORT = int(os.environ.get('PG_PORT', '5432'))
PG_DB = os.environ.get('PG_DB', 'cybersight')
PG_USER = os.environ.get('PG_USER', 'postgres')
PG_PASSWORD = os.environ.get('PG_PASSWORD', 'postgres')


class PostgreSQLConnector:
    def __init__(self):
        self._pool = psycopg2.pool.ThreadedConnectionPool(
            minconn=1, maxconn=5,
            host=PG_HOST, port=PG_PORT, dbname=PG_DB, user=PG_USER, password=PG_PASSWORD,
        )

    def _query(self, sql: str, params=None) -> pd.DataFrame:
        conn = self._pool.getconn()
        try:
            df = pd.read_sql(sql, conn, params=params)
            return df
        finally:
            self._pool.putconn(conn)

    # -----------------------------------------------------------------
    # KPI (uses summary tables)
    # -----------------------------------------------------------------
    def get_kpis(self) -> dict:
        sql = """
            WITH hourly AS (
                SELECT
                    SUM(event_count) AS total_events,
                    SUM(event_count) FILTER (WHERE attack_category <> 'Normal') AS attack_events,
                    SUM(unique_sources) FILTER (WHERE attack_category <> 'Normal') AS unique_attack_sources
                FROM summary_attack_hourly
            )
            SELECT
                COALESCE(total_events, 0) AS total_events,
                COALESCE(attack_events, 0) AS attack_events,
                CASE WHEN total_events > 0
                     THEN ROUND(attack_events * 100.0 / total_events, 2)
                     ELSE 0 END AS attack_rate,
                COALESCE(unique_attack_sources, 0) AS unique_sources
            FROM hourly
        """
        df = self._query(sql)
        if df.empty:
            return {'total_events': 0, 'attack_events': 0, 'attack_rate': 0, 'unique_sources': 0}
        return df.iloc[0].to_dict()

    # -----------------------------------------------------------------
    # Q1: Attack count by category (summary_attack_hourly)
    # -----------------------------------------------------------------
    def q1_attack_counts(self) -> pd.DataFrame:
        return self._query("""
            SELECT attack_category, SUM(event_count) AS total_events
            FROM summary_attack_hourly
            WHERE attack_category <> 'Normal'
            GROUP BY attack_category
            ORDER BY total_events DESC
        """)

    # -----------------------------------------------------------------
    # Q2: Hourly attack trend (summary_attack_hourly)
    # -----------------------------------------------------------------
    def q2_hourly_trend(self, target_date: str = None) -> pd.DataFrame:
        if target_date:
            return self._query("""
                SELECT hour_bucket, attack_category, SUM(event_count) AS event_count
                FROM summary_attack_hourly
                WHERE attack_category <> 'Normal' AND hour_bucket::date = %s
                GROUP BY hour_bucket, attack_category
                ORDER BY hour_bucket
            """, (target_date,))
        return self._query("""
            SELECT hour_bucket, attack_category, SUM(event_count) AS event_count
            FROM summary_attack_hourly
            WHERE attack_category <> 'Normal'
            GROUP BY hour_bucket, attack_category
            ORDER BY hour_bucket
        """)

    # -----------------------------------------------------------------
    # Q3: Top 10 source IPs (summary_top_sources)
    # -----------------------------------------------------------------
    def q3_top_sources(self) -> pd.DataFrame:
        return self._query("""
            SELECT source_ip::text, country,
                   SUM(attack_count) AS total_attacks,
                   SUM(distinct_targets) AS total_targets,
                   ROUND(AVG(threat_score), 2) AS threat_score
            FROM summary_top_sources
            WHERE attack_count > 0
            GROUP BY source_ip, country
            ORDER BY total_attacks DESC
            LIMIT 10
        """)

    # -----------------------------------------------------------------
    # Q4: Attack type distribution (summary_attack_hourly)
    # -----------------------------------------------------------------
    def q4_attack_distribution(self) -> pd.DataFrame:
        return self._query("""
            SELECT attack_category,
                   SUM(event_count) AS event_count,
                   ROUND(SUM(event_count) * 100.0 / SUM(SUM(event_count)) OVER (), 2) AS pct
            FROM summary_attack_hourly
            GROUP BY attack_category
            ORDER BY event_count DESC
        """)

    # -----------------------------------------------------------------
    # Q5: Protocol usage breakdown (summary_protocol_daily)
    # -----------------------------------------------------------------
    def q5_protocol_breakdown(self) -> pd.DataFrame:
        return self._query("""
            SELECT protocol_name,
                   SUM(total_events) AS total_events,
                   SUM(attack_events) AS attack_events,
                   ROUND(SUM(attack_events)::NUMERIC * 100.0 / NULLIF(SUM(total_events), 0), 2) AS attack_pct
            FROM summary_protocol_daily
            GROUP BY protocol_name
            ORDER BY total_events DESC
        """)

    # -----------------------------------------------------------------
    # Q6: Most targeted destination ports (summary_dest_port_daily)
    # -----------------------------------------------------------------
    def q6_targeted_ports(self) -> pd.DataFrame:
        return self._query("""
            SELECT dest_port, service_name, SUM(event_count) AS attack_count
            FROM summary_dest_port_daily
            GROUP BY dest_port, service_name
            ORDER BY attack_count DESC
            LIMIT 15
        """)

    # -----------------------------------------------------------------
    # Q7: Average duration by attack type (summary_attack_hourly)
    # -----------------------------------------------------------------
    def q7_avg_duration(self) -> pd.DataFrame:
        return self._query("""
            SELECT attack_label, attack_category,
                   SUM(event_count) AS event_count,
                   ROUND(SUM(avg_duration_ms * event_count) / NULLIF(SUM(event_count), 0), 2) AS avg_duration_ms,
                   ROUND(SUM(total_bytes)::NUMERIC / NULLIF(SUM(event_count), 0), 2) AS avg_total_bytes
            FROM summary_attack_hourly
            WHERE attack_category <> 'Normal'
            GROUP BY attack_label, attack_category
            ORDER BY avg_duration_ms DESC
        """)

    # -----------------------------------------------------------------
    # Q10: Attack severity over time (summary_severity_daily)
    # -----------------------------------------------------------------
    def q10_severity_over_time(self) -> pd.DataFrame:
        return self._query("""
            SELECT day_bucket AS day, severity, event_count
            FROM summary_severity_daily
            ORDER BY day_bucket, severity
        """)

    # -----------------------------------------------------------------
    # Q11: Weekend vs weekday (summary_weekend_weekday)
    # -----------------------------------------------------------------
    def q11_weekend_weekday(self) -> pd.DataFrame:
        return self._query("""
            SELECT is_weekend, attack_category, total_events, attack_events, attack_rate_pct
            FROM summary_weekend_weekday
            ORDER BY is_weekend, attack_events DESC
        """)

    # -----------------------------------------------------------------
    # Q12: Botnet activity timeline (summary_attack_hourly)
    # -----------------------------------------------------------------
    def q12_botnet_timeline(self) -> pd.DataFrame:
        return self._query("""
            SELECT hour_bucket, SUM(event_count) AS bot_events,
                   SUM(unique_sources) AS unique_bot_sources,
                   SUM(total_bytes) AS total_bytes
            FROM summary_attack_hourly
            WHERE attack_category = 'Botnet'
            GROUP BY hour_bucket
            ORDER BY hour_bucket
        """)

    # =================================================================
    # FACT-TABLE queries (star-schema JOINs, no summary tables)
    # Used by Backend Comparison for a fair cross-engine benchmark.
    # =================================================================

    def q1_attack_counts_fact(self) -> pd.DataFrame:
        return self._query("""
            SELECT da.attack_category, COUNT(*) AS total_events
            FROM fact_network_event f
            JOIN dim_attack da ON f.attack_key = da.attack_key
            WHERE f.is_attack = TRUE
            GROUP BY da.attack_category
            ORDER BY total_events DESC
        """)

    def q2_hourly_trend_fact(self) -> pd.DataFrame:
        return self._query("""
            SELECT date_trunc('hour', dt.timestamp) AS hour_bucket,
                   da.attack_category,
                   COUNT(*) AS event_count
            FROM fact_network_event f
            JOIN dim_time dt    ON f.time_key   = dt.time_key
            JOIN dim_attack da  ON f.attack_key = da.attack_key
            WHERE f.is_attack = TRUE
            GROUP BY hour_bucket, da.attack_category
            ORDER BY hour_bucket
        """)

    def q3_top_sources_fact(self) -> pd.DataFrame:
        return self._query("""
            SELECT ds.source_ip::text, ds.country,
                   COUNT(*) AS total_attacks
            FROM fact_network_event f
            JOIN dim_source ds  ON f.source_key = ds.source_key
            WHERE f.is_attack = TRUE
            GROUP BY ds.source_ip, ds.country
            ORDER BY total_attacks DESC
            LIMIT 10
        """)

    def q4_attack_distribution_fact(self) -> pd.DataFrame:
        return self._query("""
            SELECT da.attack_category,
                   COUNT(*) AS event_count,
                   ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 2) AS pct
            FROM fact_network_event f
            JOIN dim_attack da ON f.attack_key = da.attack_key
            GROUP BY da.attack_category
            ORDER BY event_count DESC
        """)

    def q5_protocol_breakdown_fact(self) -> pd.DataFrame:
        return self._query("""
            SELECT dp.protocol_name,
                   COUNT(*) AS total_events,
                   SUM(CASE WHEN f.is_attack THEN 1 ELSE 0 END) AS attack_events,
                   ROUND(
                       SUM(CASE WHEN f.is_attack THEN 1 ELSE 0 END)::NUMERIC
                       * 100.0 / NULLIF(COUNT(*), 0), 2
                   ) AS attack_pct
            FROM fact_network_event f
            JOIN dim_protocol dp ON f.protocol_key = dp.protocol_key
            GROUP BY dp.protocol_name
            ORDER BY total_events DESC
        """)

    def q6_targeted_ports_fact(self) -> pd.DataFrame:
        return self._query("""
            SELECT dd.dest_port, dd.service_name, COUNT(*) AS attack_count
            FROM fact_network_event f
            JOIN dim_destination dd ON f.dest_key = dd.dest_key
            WHERE f.is_attack = TRUE
            GROUP BY dd.dest_port, dd.service_name
            ORDER BY attack_count DESC
            LIMIT 15
        """)

    def q7_avg_duration_fact(self) -> pd.DataFrame:
        return self._query("""
            SELECT da.attack_label, da.attack_category,
                   COUNT(*) AS event_count,
                   ROUND(AVG(f.flow_duration / 1000.0), 2) AS avg_duration_ms,
                   ROUND(AVG(f.fwd_bytes + f.bwd_bytes)::NUMERIC, 2) AS avg_total_bytes
            FROM fact_network_event f
            JOIN dim_attack da ON f.attack_key = da.attack_key
            WHERE f.is_attack = TRUE
            GROUP BY da.attack_label, da.attack_category
            ORDER BY avg_duration_ms DESC
        """)

    def q9_country_summary_fact(self) -> pd.DataFrame:
        return self._query("""
            SELECT ds.country,
                   COUNT(*) AS attack_events,
                   COUNT(DISTINCT ds.source_ip) AS unique_ips
            FROM fact_network_event f
            JOIN dim_source ds ON f.source_key = ds.source_key
            WHERE f.is_attack = TRUE
            GROUP BY ds.country
            ORDER BY attack_events DESC
        """)

    def q10_severity_over_time_fact(self) -> pd.DataFrame:
        return self._query("""
            SELECT dt.timestamp::date AS day_bucket,
                   da.severity,
                   COUNT(*) AS event_count
            FROM fact_network_event f
            JOIN dim_time dt   ON f.time_key   = dt.time_key
            JOIN dim_attack da ON f.attack_key = da.attack_key
            WHERE f.is_attack = TRUE
            GROUP BY dt.timestamp::date, da.severity
            ORDER BY dt.timestamp::date, da.severity
        """)

    def q11_weekend_weekday_fact(self) -> pd.DataFrame:
        return self._query("""
            SELECT dt.is_weekend,
                   da.attack_category,
                   COUNT(*) AS total_events,
                   SUM(CASE WHEN f.is_attack THEN 1 ELSE 0 END) AS attack_events,
                   ROUND(
                       SUM(CASE WHEN f.is_attack THEN 1 ELSE 0 END)::NUMERIC
                       * 100.0 / NULLIF(COUNT(*), 0), 2
                   ) AS attack_rate_pct
            FROM fact_network_event f
            JOIN dim_time dt   ON f.time_key   = dt.time_key
            JOIN dim_attack da ON f.attack_key = da.attack_key
            GROUP BY dt.is_weekend, da.attack_category
            ORDER BY dt.is_weekend, attack_events DESC
        """)

    def q12_botnet_timeline_fact(self) -> pd.DataFrame:
        return self._query("""
            SELECT date_trunc('hour', dt.timestamp) AS hour_bucket,
                   COUNT(*) AS bot_events,
                   SUM(f.fwd_bytes + f.bwd_bytes) AS total_bytes
            FROM fact_network_event f
            JOIN dim_time dt   ON f.time_key   = dt.time_key
            JOIN dim_attack da ON f.attack_key = da.attack_key
            WHERE da.attack_category = 'Botnet'
            GROUP BY hour_bucket
            ORDER BY hour_bucket
        """)

    # -----------------------------------------------------------------
    # Time analysis helpers (from summary tables)
    # -----------------------------------------------------------------
    def get_day_of_week_heatmap(self) -> pd.DataFrame:
        return self._query("""
            SELECT dt.day_of_week, dt.hour, SUM(sah.event_count) AS event_count
            FROM summary_attack_hourly sah
            JOIN dim_time dt ON sah.hour_bucket = dt.timestamp
            WHERE sah.attack_category <> 'Normal'
            GROUP BY dt.day_of_week, dt.hour
            ORDER BY dt.day_of_week, dt.hour
        """)

    def get_time_of_day_distribution(self) -> pd.DataFrame:
        return self._query("""
            SELECT dt.time_of_day, sah.attack_category, SUM(sah.event_count) AS event_count
            FROM summary_attack_hourly sah
            JOIN dim_time dt ON sah.hour_bucket = dt.timestamp
            WHERE sah.attack_category <> 'Normal'
            GROUP BY dt.time_of_day, sah.attack_category
            ORDER BY event_count DESC
        """)

    def get_weekly_trend(self) -> pd.DataFrame:
        return self._query("""
            SELECT dt.year, dt.week, sah.attack_category, SUM(sah.event_count) AS event_count
            FROM summary_attack_hourly sah
            JOIN dim_time dt ON sah.hour_bucket = dt.timestamp
            WHERE sah.attack_category <> 'Normal'
            GROUP BY dt.year, dt.week, sah.attack_category
            ORDER BY dt.year, dt.week
        """)

    def get_country_summary(self) -> pd.DataFrame:
        return self._query("""
            SELECT country,
                   SUM(attack_count) AS attack_events,
                   COUNT(DISTINCT source_ip) AS unique_ips
            FROM summary_top_sources
            GROUP BY country
            ORDER BY attack_events DESC
        """)

    def get_available_dates(self) -> list:
        df = self._query("""
            SELECT DISTINCT date_trunc('day', timestamp)::date AS day
            FROM dim_time ORDER BY day
        """)
        return df['day'].tolist() if not df.empty else []

    # -----------------------------------------------------------------
    # Filter helpers — fetch available values from dimension tables
    # -----------------------------------------------------------------
    def get_distinct_categories(self) -> list:
        df = self._query("SELECT DISTINCT attack_category FROM dim_attack ORDER BY attack_category")
        return df['attack_category'].tolist() if not df.empty else []

    def get_distinct_protocols(self) -> list:
        df = self._query("SELECT DISTINCT protocol_name FROM dim_protocol ORDER BY protocol_name")
        return df['protocol_name'].tolist() if not df.empty else []

    def get_distinct_severities(self) -> list:
        df = self._query("SELECT DISTINCT severity FROM dim_attack ORDER BY severity")
        return df['severity'].tolist() if not df.empty else []
