-- Q5: Protocol usage breakdown
-- Backend: All | Uses Summary: Yes (summary_protocol_daily)

SELECT
    protocol_name,
    SUM(total_events)  AS total_events,
    SUM(attack_events) AS attack_events,
    ROUND(
        SUM(attack_events)::NUMERIC * 100.0 / NULLIF(SUM(total_events), 0), 2
    ) AS attack_pct
FROM summary_protocol_daily
GROUP BY protocol_name
ORDER BY total_events DESC;
