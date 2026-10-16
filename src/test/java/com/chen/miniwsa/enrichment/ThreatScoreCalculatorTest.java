package com.chen.miniwsa.enrichment;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import com.chen.miniwsa.event.Action;
import com.chen.miniwsa.event.Severity;

class ThreatScoreCalculatorTest {

	private static final String PLAIN_PATH = "/products";

	@Test
	void severityPoints() {
		assertThat(ThreatScoreCalculator.calculate(Severity.CRITICAL, Action.MONITOR, PLAIN_PATH, 0)).isEqualTo(40);
		assertThat(ThreatScoreCalculator.calculate(Severity.HIGH, Action.MONITOR, PLAIN_PATH, 0)).isEqualTo(30);
		assertThat(ThreatScoreCalculator.calculate(Severity.MEDIUM, Action.MONITOR, PLAIN_PATH, 0)).isEqualTo(20);
		assertThat(ThreatScoreCalculator.calculate(Severity.LOW, Action.MONITOR, PLAIN_PATH, 0)).isEqualTo(10);
	}

	@Test
	void actionPoints() {
		assertThat(ThreatScoreCalculator.calculate(Severity.LOW, Action.DENY, PLAIN_PATH, 0)).isEqualTo(30);
		assertThat(ThreatScoreCalculator.calculate(Severity.LOW, Action.ALERT, PLAIN_PATH, 0)).isEqualTo(20);
		assertThat(ThreatScoreCalculator.calculate(Severity.LOW, Action.MONITOR, PLAIN_PATH, 0)).isEqualTo(10);
	}

	@Test
	void sensitivePathAddsBonus() {
		assertThat(ThreatScoreCalculator.calculate(Severity.LOW, Action.MONITOR, "/admin/users", 0)).isEqualTo(25);
		assertThat(ThreatScoreCalculator.calculate(Severity.LOW, Action.MONITOR, "/api/v1/login", 0)).isEqualTo(25);
	}

	@Test
	void repeatOffenderBonusNeedsMoreThanFiveEvents() {
		assertThat(ThreatScoreCalculator.calculate(Severity.LOW, Action.MONITOR, PLAIN_PATH, 5)).isEqualTo(10);
		assertThat(ThreatScoreCalculator.calculate(Severity.LOW, Action.MONITOR, PLAIN_PATH, 6)).isEqualTo(25);
	}

	@Test
	void allBonusesTogether() {
		assertThat(ThreatScoreCalculator.calculate(Severity.CRITICAL, Action.DENY, "/admin", 6)).isEqualTo(90);
	}
}
