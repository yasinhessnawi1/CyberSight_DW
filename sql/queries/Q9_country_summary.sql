-- Q9: Country-level threat summary
-- Backend: All | Uses Summary: Yes (summary_top_sources)

SELECT
    country,
    SUM(attack_count) AS attack_events,
    COUNT(DISTINCT source_ip) AS unique_ips,
    ROUND(AVG(threat_score), 2) AS avg_threat_score
FROM summary_top_sources
GROUP BY country
ORDER BY attack_events DESC;
