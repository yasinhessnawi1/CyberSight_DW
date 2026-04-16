-- Q12: Botnet activity timeline
-- Backend: All | Uses Summary: Yes (summary_attack_hourly)

SELECT
    hour_bucket,
    SUM(event_count) AS bot_events,
    SUM(unique_sources) AS unique_bot_sources,
    SUM(total_bytes) AS total_bytes
FROM summary_attack_hourly
WHERE attack_category = 'Botnet'
GROUP BY hour_bucket
ORDER BY hour_bucket;
