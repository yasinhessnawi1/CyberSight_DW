-- Q11: Weekend vs weekday attack comparison
-- Backend: All | Uses Summary: Yes (summary_weekend_weekday)

SELECT
    is_weekend,
    attack_category,
    total_events,
    attack_events,
    attack_rate_pct
FROM summary_weekend_weekday
ORDER BY is_weekend, attack_events DESC;
