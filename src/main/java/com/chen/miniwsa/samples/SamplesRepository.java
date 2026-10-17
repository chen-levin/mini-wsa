package com.chen.miniwsa.samples;

import java.time.Instant;
import java.util.List;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.Repository;

import com.chen.miniwsa.event.Action;
import com.chen.miniwsa.event.Category;
import com.chen.miniwsa.event.SecurityEvent;

// configId, category and action are optional (null = don't filter). from/to are always set: [from, to)
public interface SamplesRepository extends Repository<SecurityEvent, Long> {

	@Query("""
			SELECT e
			FROM SecurityEvent e
			WHERE (:configId IS NULL OR e.configId = :configId)
			  AND e.eventTime >= :from AND e.eventTime < :to
			  AND (:category IS NULL OR e.ruleCategory = :category)
			  AND (:action IS NULL OR e.action = :action)
			ORDER BY e.eventTime DESC, e.id DESC
			LIMIT :limit OFFSET :offset
			""")
	List<SecurityEvent> findSamples(Long configId, Instant from, Instant to,
			Category category, Action action, int limit, int offset);

	@Query("""
			SELECT COUNT(e)
			FROM SecurityEvent e
			WHERE (:configId IS NULL OR e.configId = :configId)
			  AND e.eventTime >= :from AND e.eventTime < :to
			  AND (:category IS NULL OR e.ruleCategory = :category)
			  AND (:action IS NULL OR e.action = :action)
			""")
	long countSamples(Long configId, Instant from, Instant to,
			Category category, Action action);
}
