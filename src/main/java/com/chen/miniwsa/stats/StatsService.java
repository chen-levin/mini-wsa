package com.chen.miniwsa.stats;

import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.chen.miniwsa.event.Action;
import com.chen.miniwsa.event.Category;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class StatsService {

	private final StatsRepository statsRepository;

	@Transactional(readOnly = true)
	public StatsSummaryResponse summary(Long configId, Instant from, Instant to) {
		long totalEvents = statsRepository.countEvents(configId, from, to);

		// Start every category and action at zero, so the response always has all of them
		Map<Category, CategoryStats> byCategory = new EnumMap<>(Category.class);
		for (Category category : Category.values()) {
			byCategory.put(category, new CategoryStats(0, 0.0));
		}
		for (CategoryRow row : statsRepository.countByCategory(configId, from, to)) {
			byCategory.put(row.category(), new CategoryStats(row.count(), round(row.avgThreatScore())));
		}

		Map<Action, Long> byAction = new EnumMap<>(Action.class);
		for (Action action : Action.values()) {
			byAction.put(action, 0L);
		}
		for (ActionRow row : statsRepository.countByAction(configId, from, to)) {
			byAction.put(row.action(), row.count());
		}

		List<AttackerStats> topAttackers = new ArrayList<>();
		for (AttackerRow row : statsRepository.topAttackers(configId, from, to)) {
			topAttackers.add(new AttackerStats(row.clientIp(), row.count(), round(row.avgThreatScore())));
		}

		List<PathStats> topTargetedPaths = new ArrayList<>();
		for (PathRow row : statsRepository.topPaths(configId, from, to)) {
			topTargetedPaths.add(new PathStats(row.path(), row.count()));
		}

		return new StatsSummaryResponse(
				configId,
				new TimeRange(from, to),
				totalEvents,
				byCategory,
				byAction,
				topAttackers,
				topTargetedPaths);
	}

	// One decimal place, e.g. 72.3333 -> 72.3
	private double round(double value) {
		return Math.round(value * 10) / 10.0;
	}
}
