package com.chen.miniwsa.stats;

import java.util.List;
import java.util.Map;

import com.chen.miniwsa.event.Action;
import com.chen.miniwsa.event.Category;

public record StatsSummaryResponse(
		Long configId,
		TimeRange timeRange,
		long totalEvents,
		Map<Category, CategoryStats> byCategory,
		Map<Action, Long> byAction,
		List<AttackerStats> topAttackers,
		List<PathStats> topTargetedPaths) {
}
