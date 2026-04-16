-- Q4: Attack type distribution (BENIGN vs attacks)
-- Backend: All | Uses Summary: Yes (summary_attack_hourly)

SELECT
    attack_category,
    SUM(event_count) AS event_count,
    ROUND(SUM(event_count) * 100.0 / SUM(SUM(event_count)) OVER (), 2) AS pct
FROM summary_attack_hourly
GROUP BY attack_category
ORDER BY event_count DESC;
