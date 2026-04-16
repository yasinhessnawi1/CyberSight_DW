-- ============================================================
-- Batch Job: Populate summary_dest_port_daily
-- Run after each load of fact_network_event
-- ============================================================

INSERT INTO summary_dest_port_daily
    (day_bucket, dest_port, service_name, attack_category, event_count)
SELECT
    date_trunc('day', dt.timestamp)::DATE  AS day_bucket,
    dd.dest_port,
    dd.service_name,
    da.attack_category,
    COUNT(*)                               AS event_count
FROM fact_network_event f
JOIN dim_time        dt ON f.time_key   = dt.time_key
JOIN dim_destination dd ON f.dest_key   = dd.dest_key
JOIN dim_attack      da ON f.attack_key = da.attack_key
WHERE f.is_attack = TRUE
GROUP BY date_trunc('day', dt.timestamp)::DATE, dd.dest_port, dd.service_name, da.attack_category
ON CONFLICT (day_bucket, dest_port, attack_category)
DO UPDATE SET
    service_name = EXCLUDED.service_name,
    event_count  = EXCLUDED.event_count,
    created_at   = NOW();
