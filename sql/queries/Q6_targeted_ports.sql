-- Q6: Most targeted destination ports
-- Backend: All | Uses Summary: Yes (summary_dest_port_daily)

SELECT
    dest_port,
    service_name,
    SUM(event_count) AS attack_count
FROM summary_dest_port_daily
GROUP BY dest_port, service_name
ORDER BY attack_count DESC
LIMIT 15;
