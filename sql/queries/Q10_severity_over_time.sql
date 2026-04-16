-- Q10: Attack severity distribution over time
-- Backend: All | Uses Summary: Yes (summary_severity_daily)

SELECT
    day_bucket AS day,
    severity,
    event_count
FROM summary_severity_daily
ORDER BY day_bucket, severity;
