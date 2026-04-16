-- ============================================================
-- CyberSight DW — ksqlDB Streaming Definitions
-- Applied automatically by the ksqldb-init service on startup.
-- ============================================================

-- Stream over the raw Kafka topic
CREATE STREAM IF NOT EXISTS network_events_stream (
    flow_id         VARCHAR,
    source_ip       VARCHAR,
    source_port     INTEGER,
    destination_ip  VARCHAR,
    destination_port INTEGER,
    protocol        VARCHAR,
    timestamp       VARCHAR,
    flow_duration   BIGINT,
    fwd_packets     INTEGER,
    bwd_packets     INTEGER,
    fwd_bytes       BIGINT,
    bwd_bytes       BIGINT,
    flow_bytes_per_sec  DOUBLE,
    flow_packets_per_sec DOUBLE,
    label           VARCHAR,
    attack_category VARCHAR,
    severity        VARCHAR,
    source_country  VARCHAR,
    source_region   VARCHAR
) WITH (
    KAFKA_TOPIC  = 'network-events',
    VALUE_FORMAT = 'JSON'
);

-- 1-minute tumbling window: attack rate per category
CREATE TABLE IF NOT EXISTS attack_rate_1min AS
SELECT
    attack_category,
    COUNT(*)       AS event_count,
    WINDOWSTART    AS window_start,
    WINDOWEND      AS window_end
FROM network_events_stream
WINDOW TUMBLING (SIZE 1 MINUTE)
WHERE attack_category <> 'Normal'
GROUP BY attack_category
EMIT CHANGES;

-- 1-minute tumbling window: events per protocol
CREATE TABLE IF NOT EXISTS protocol_rate_1min AS
SELECT
    protocol,
    COUNT(*)       AS event_count,
    WINDOWSTART    AS window_start
FROM network_events_stream
WINDOW TUMBLING (SIZE 1 MINUTE)
GROUP BY protocol
EMIT CHANGES;

-- 5-minute tumbling window: high-volume attack sources (> 100 events)
CREATE TABLE IF NOT EXISTS high_volume_sources AS
SELECT
    source_ip,
    COUNT(*)       AS attack_count,
    WINDOWSTART    AS window_start
FROM network_events_stream
WINDOW TUMBLING (SIZE 5 MINUTES)
WHERE attack_category <> 'Normal'
GROUP BY source_ip
HAVING COUNT(*) > 100
EMIT CHANGES;
