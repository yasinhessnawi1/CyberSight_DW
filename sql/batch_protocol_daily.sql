-- ============================================================
-- Batch Job: Populate summary_protocol_daily
-- Run after each load of fact_network_event
-- ============================================================

INSERT INTO summary_protocol_daily
    (day_bucket, protocol_name, total_events, attack_events, attack_ratio)
SELECT
    date_trunc('day', dt.timestamp)::DATE  AS day_bucket,
    dp.protocol_name,
    COUNT(*)                               AS total_events,
    COUNT(*) FILTER (WHERE f.is_attack = TRUE) AS attack_events,
    ROUND(
        COUNT(*) FILTER (WHERE f.is_attack = TRUE)::NUMERIC
        / NULLIF(COUNT(*), 0), 4
    )                                      AS attack_ratio
FROM fact_network_event f
JOIN dim_time     dt ON f.time_key     = dt.time_key
JOIN dim_protocol dp ON f.protocol_key = dp.protocol_key
GROUP BY date_trunc('day', dt.timestamp)::DATE, dp.protocol_name
ON CONFLICT (day_bucket, protocol_name)
DO UPDATE SET
    total_events  = EXCLUDED.total_events,
    attack_events = EXCLUDED.attack_events,
    attack_ratio  = EXCLUDED.attack_ratio;
