-- ============================================================
-- Batch Job: Populate summary_weekend_weekday
-- Run after each load of fact_network_event
-- ============================================================

INSERT INTO summary_weekend_weekday
    (is_weekend, attack_category, total_events, attack_events, attack_rate_pct)
SELECT
    dt.is_weekend,
    da.attack_category,
    COUNT(*)                                     AS total_events,
    COUNT(*) FILTER (WHERE f.is_attack = TRUE)   AS attack_events,
    ROUND(
        COUNT(*) FILTER (WHERE f.is_attack = TRUE) * 100.0 / NULLIF(COUNT(*), 0), 2
    )                                            AS attack_rate_pct
FROM fact_network_event f
JOIN dim_time   dt ON f.time_key   = dt.time_key
JOIN dim_attack da ON f.attack_key = da.attack_key
GROUP BY dt.is_weekend, da.attack_category
ON CONFLICT (is_weekend, attack_category)
DO UPDATE SET
    total_events    = EXCLUDED.total_events,
    attack_events   = EXCLUDED.attack_events,
    attack_rate_pct = EXCLUDED.attack_rate_pct,
    created_at      = NOW();
