-- Q8: Co-attacking IPs (shared attack type)
-- Backend: Neo4j only | Uses Summary: No
-- This query is best expressed in Cypher (see Neo4j connector).
-- PostgreSQL equivalent below is for reference only.

SELECT
    ds1.source_ip AS ip1,
    ds2.source_ip AS ip2,
    da.attack_label AS shared_attack,
    COUNT(*) AS co_count
FROM fact_network_event f1
JOIN fact_network_event f2
    ON f1.attack_key = f2.attack_key
    AND f1.source_key < f2.source_key
JOIN dim_source ds1 ON f1.source_key = ds1.source_key
JOIN dim_source ds2 ON f2.source_key = ds2.source_key
JOIN dim_attack da  ON f1.attack_key = da.attack_key
WHERE f1.is_attack = TRUE
GROUP BY ds1.source_ip, ds2.source_ip, da.attack_label
ORDER BY co_count DESC
LIMIT 20;
