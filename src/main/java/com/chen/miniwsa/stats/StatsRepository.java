package com.chen.miniwsa.stats;

import java.time.Instant;
import java.util.List;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.Repository;

import com.chen.miniwsa.event.SecurityEvent;

// All queries: configId is optional (null = all configs), time range is [from, to)
public interface StatsRepository extends Repository<SecurityEvent, Long> {

	@Query("""
			SELECT COUNT(e)
			FROM SecurityEvent e
			WHERE (:configId IS NULL OR e.configId = :configId)
			  AND e.eventTime >= :from AND e.eventTime < :to
			""")
	long countEvents(Long configId, Instant from, Instant to);

	@Query("""
			SELECT new com.chen.miniwsa.stats.CategoryRow(e.ruleCategory, COUNT(e), AVG(e.threatScore))
			FROM SecurityEvent e
			WHERE (:configId IS NULL OR e.configId = :configId)
			  AND e.eventTime >= :from AND e.eventTime < :to
			GROUP BY e.ruleCategory
			""")
	List<CategoryRow> countByCategory(Long configId, Instant from, Instant to);

	@Query("""
			SELECT new com.chen.miniwsa.stats.ActionRow(e.action, COUNT(e))
			FROM SecurityEvent e
			WHERE (:configId IS NULL OR e.configId = :configId)
			  AND e.eventTime >= :from AND e.eventTime < :to
			GROUP BY e.action
			""")
	List<ActionRow> countByAction(Long configId, Instant from, Instant to);

	@Query("""
			SELECT new com.chen.miniwsa.stats.AttackerRow(e.clientIp, COUNT(e), AVG(e.threatScore))
			FROM SecurityEvent e
			WHERE (:configId IS NULL OR e.configId = :configId)
			  AND e.eventTime >= :from AND e.eventTime < :to
			GROUP BY e.clientIp
			ORDER BY COUNT(e) DESC, e.clientIp
			LIMIT 10
			""")
	List<AttackerRow> topAttackers(Long configId, Instant from, Instant to);

	@Query("""
			SELECT new com.chen.miniwsa.stats.PathRow(e.path, COUNT(e))
			FROM SecurityEvent e
			WHERE (:configId IS NULL OR e.configId = :configId)
			  AND e.eventTime >= :from AND e.eventTime < :to
			GROUP BY e.path
			ORDER BY COUNT(e) DESC, e.path
			LIMIT 10
			""")
	List<PathRow> topPaths(Long configId, Instant from, Instant to);
}
