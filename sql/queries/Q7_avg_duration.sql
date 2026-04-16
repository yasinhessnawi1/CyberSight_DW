-- Q7: Average flow duration by attack type
-- Backend: All | Uses Summary: Yes (summary_attack_hourly)

SELECT
    attack_label,
    attack_category,
    SUM(event_count) AS event_count,
    ROUND(SUM(avg_duration_ms * event_count) / NULLIF(SUM(event_count), 0), 2) AS avg_duration_ms,
    ROUND(SUM(total_bytes)::NUMERIC / NULLIF(SUM(event_count), 0), 2) AS avg_total_bytes
FROM summary_attack_hourly
WHERE attack_category <> 'Normal'
GROUP BY attack_label, attack_category
ORDER BY avg_duration_ms DESC;
