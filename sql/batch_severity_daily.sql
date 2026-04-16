-- ============================================================
-- Batch Job: Populate summary_severity_daily
-- Run after each load of fact_network_event
-- ============================================================

INSERT INTO summary_severity_daily
    (day_bucket, severity, event_count, unique_sources)
SELECT
    date_trunc('day', dt.timestamp)::DATE  AS day_bucket,
    da.severity,
    COUNT(*)                               AS event_count,
    COUNT(DISTINCT f.source_key)           AS unique_sources
FROM fact_network_event f
JOIN dim_time   dt ON f.time_key   = dt.time_key
JOIN dim_attack da ON f.attack_key = da.attack_key
WHERE f.is_attack = TRUE
GROUP BY date_trunc('day', dt.timestamp)::DATE, da.severity
ON CONFLICT (day_bucket, severity)
DO UPDATE SET
    event_count    = EXCLUDED.event_count,
    unique_sources = EXCLUDED.unique_sources,
    created_at     = NOW();
