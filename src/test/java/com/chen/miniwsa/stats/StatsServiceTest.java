package com.chen.miniwsa.stats;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.chen.miniwsa.event.Action;
import com.chen.miniwsa.event.Category;

@ExtendWith(MockitoExtension.class)
class StatsServiceTest {

	private static final Long CONFIG_ID = 14227L;
	private static final Instant FROM = Instant.parse("2026-05-20T00:00:00Z");
	private static final Instant TO = Instant.parse("2026-05-21T00:00:00Z");

	// A fake repository: returns whatever each test tells it to, no database
	@Mock
	private StatsRepository statsRepository;

	private StatsService statsService;

	@BeforeEach
	void setUp() {
		statsService = new StatsService(statsRepository);
	}

	@Test
	void fillsMissingCategoriesAndActionsWithZero() {
		when(statsRepository.countByCategory(CONFIG_ID, FROM, TO))
				.thenReturn(List.of(new CategoryRow(Category.BOT, 3L, 10.0)));
		when(statsRepository.countByAction(CONFIG_ID, FROM, TO))
				.thenReturn(List.of(new ActionRow(Action.DENY, 3L)));

		StatsSummaryResponse response = statsService.summary(CONFIG_ID, FROM, TO);

		assertThat(response.byCategory()).hasSize(Category.values().length);
		assertThat(response.byCategory().get(Category.BOT).count()).isEqualTo(3);
		assertThat(response.byCategory().get(Category.XSS).count()).isZero();

		assertThat(response.byAction()).hasSize(Action.values().length);
		assertThat(response.byAction().get(Action.DENY)).isEqualTo(3);
		assertThat(response.byAction().get(Action.MONITOR)).isZero();
	}

	@Test
	void roundsAveragesToOneDecimal() {
		when(statsRepository.countByCategory(CONFIG_ID, FROM, TO))
				.thenReturn(List.of(new CategoryRow(Category.INJECTION, 3L, 72.3333)));
		when(statsRepository.topAttackers(CONFIG_ID, FROM, TO))
				.thenReturn(List.of(new AttackerRow("1.1.1.1", 3L, 46.6667)));

		StatsSummaryResponse response = statsService.summary(CONFIG_ID, FROM, TO);

		assertThat(response.byCategory().get(Category.INJECTION).avgThreatScore()).isEqualTo(72.3);
		assertThat(response.topAttackers().get(0).avgThreatScore()).isEqualTo(46.7);
	}
}
