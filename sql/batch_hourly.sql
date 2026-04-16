-- ============================================================
-- Batch Job: Populate summary_attack_hourly
-- Run after each load of fact_network_event
-- ============================================================

INSERT INTO summary_attack_hourly
    (hour_bucket, attack_category, attack_label, event_count,
     total_bytes, avg_duration_ms, unique_sources)
SELECT
    date_trunc('hour', dt.timestamp)     AS hour_bucket,
    da.attack_category,
    da.attack_label,
    COUNT(*)                             AS event_count,
    SUM(f.fwd_bytes + f.bwd_bytes)       AS total_bytes,
    AVG(f.flow_duration / 1000.0)        AS avg_duration_ms,
    COUNT(DISTINCT f.source_key)         AS unique_sources
FROM fact_network_event f
JOIN dim_time   dt ON f.time_key   = dt.time_key
JOIN dim_attack da ON f.attack_key = da.attack_key
GROUP BY date_trunc('hour', dt.timestamp), da.attack_category, da.attack_label
ON CONFLICT (hour_bucket, attack_label)
DO UPDATE SET
    event_count    = EXCLUDED.event_count,
    total_bytes    = EXCLUDED.total_bytes,
    avg_duration_ms= EXCLUDED.avg_duration_ms,
    unique_sources = EXCLUDED.unique_sources,
    created_at     = NOW();
