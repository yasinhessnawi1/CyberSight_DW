-- ============================================================
-- Batch Job: Populate summary_top_sources
-- Run after each load of fact_network_event
-- ============================================================

INSERT INTO summary_top_sources
    (day_bucket, source_ip, country, attack_count,
     distinct_targets, primary_attack, threat_score)
SELECT
    date_trunc('day', dt.timestamp)::DATE AS day_bucket,
    ds.source_ip,
    ds.country,
    COUNT(*)  FILTER (WHERE f.is_attack = TRUE) AS attack_count,
    COUNT(DISTINCT f.dest_key)                  AS distinct_targets,
    MODE() WITHIN GROUP (ORDER BY da.attack_label) AS primary_attack,
    ROUND(
        (COUNT(*) FILTER (WHERE f.is_attack = TRUE)::NUMERIC / NULLIF(COUNT(*), 0))
        * COUNT(DISTINCT f.dest_key)
        * CASE MAX(da.severity)
            WHEN 'CRITICAL' THEN 4
            WHEN 'HIGH'     THEN 3
            WHEN 'MEDIUM'   THEN 2
            ELSE 1
          END
    , 2) AS threat_score
FROM fact_network_event f
JOIN dim_time   dt ON f.time_key   = dt.time_key
JOIN dim_source ds ON f.source_key = ds.source_key
JOIN dim_attack da ON f.attack_key = da.attack_key
GROUP BY date_trunc('day', dt.timestamp)::DATE, ds.source_ip, ds.country
ON CONFLICT (day_bucket, source_ip)
DO UPDATE SET
    attack_count     = EXCLUDED.attack_count,
    distinct_targets = EXCLUDED.distinct_targets,
    primary_attack   = EXCLUDED.primary_attack,
    threat_score     = EXCLUDED.threat_score,
    created_at       = NOW();
