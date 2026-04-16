-- Q2: Hourly attack volume trend for a given day
-- Backend: All | Uses Summary: Yes
-- Parameter: target_date (e.g. '2017-07-05')

SELECT
    hour_bucket,
    attack_category,
    SUM(event_count) AS event_count
FROM summary_attack_hourly
WHERE hour_bucket::date = :target_date
  AND attack_category <> 'Normal'
GROUP BY hour_bucket, attack_category
ORDER BY hour_bucket;
