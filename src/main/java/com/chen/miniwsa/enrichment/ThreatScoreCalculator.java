package com.chen.miniwsa.enrichment;

import com.chen.miniwsa.event.Action;
import com.chen.miniwsa.event.Severity;

public class ThreatScoreCalculator {

	private static final int SENSITIVE_PATH_BONUS = 15;
	private static final int REPEAT_OFFENDER_BONUS = 15;
	private static final int REPEAT_OFFENDER_THRESHOLD = 5;
	private static final int MAX_SCORE = 100;

	public static int calculate(Severity severity, Action action, String path, long recentEventsFromSameIp) {
		int score = severityPoints(severity) + actionPoints(action);

		if (path.contains("/admin") || path.contains("/login")) {
			score += SENSITIVE_PATH_BONUS;
		}

		if (recentEventsFromSameIp > REPEAT_OFFENDER_THRESHOLD) {
			score += REPEAT_OFFENDER_BONUS;
		}

		return Math.min(score, MAX_SCORE);
	}

	private static int severityPoints(Severity severity) {
		return switch (severity) {
			case CRITICAL -> 40;
			case HIGH -> 30;
			case MEDIUM -> 20;
			case LOW -> 10;
		};
	}

	private static int actionPoints(Action action) {
		return switch (action) {
			case DENY -> 20;
			case ALERT -> 10;
			case MONITOR -> 0;
		};
	}
}
