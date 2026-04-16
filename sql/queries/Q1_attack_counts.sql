-- Q1: Total attack count by category
-- Backend: All | Uses Summary: Yes

SELECT
    attack_category,
    SUM(event_count) AS total_events
FROM summary_attack_hourly
WHERE attack_category <> 'Normal'
GROUP BY attack_category
ORDER BY total_events DESC;
