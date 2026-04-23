-- Q3: Top 10 source IPs by attack count
-- Backend: All | Uses Summary: Yes

SELECT
    source_ip,
    country,
    SUM(attack_count)    AS total_attacks,
    SUM(distinct_targets) AS total_targets,
    MAX(threat_score)    AS max_threat_score
FROM summary_top_sources
WHERE attack_count > 0
GROUP BY source_ip, country
ORDER BY total_attacks DESC
LIMIT 10; 
