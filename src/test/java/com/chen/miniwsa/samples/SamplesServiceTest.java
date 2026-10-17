package com.chen.miniwsa.samples;

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
import com.chen.miniwsa.event.SecurityEvent;
import com.chen.miniwsa.event.Severity;

@ExtendWith(MockitoExtension.class)
class SamplesServiceTest {

	private static final Instant EARLIEST = Instant.EPOCH;
	private static final Instant LATEST = Instant.parse("9999-12-31T23:59:59Z");

	@Mock
	private SamplesRepository samplesRepository;

	private SamplesService samplesService;

	@BeforeEach
	void setUp() {
		samplesService = new SamplesService(samplesRepository);
	}

	@Test
	void missingFromAndToMeanTheWholeTimeRange() {
		// Strict Mockito: if the service passed other from/to values, this stub would not match and the test fails
		when(samplesRepository.findSamples(null, EARLIEST, LATEST, null, null, 20, 0))
				.thenReturn(List.of(entity("e1", "CN", "Beijing")));
		when(samplesRepository.countSamples(null, EARLIEST, LATEST, null, null))
				.thenReturn(1L);

		SamplesResponse response = samplesService.samples(null, null, null, null, null, 20, 0);

		assertThat(response.total()).isEqualTo(1);
		assertThat(response.events()).hasSize(1);
	}

	@Test
	void rebuildsNestedRuleAndGeoLocation() {
		when(samplesRepository.findSamples(null, EARLIEST, LATEST, null, null, 20, 0))
				.thenReturn(List.of(entity("e1", "CN", "Beijing")));

		SampleEvent sample = samplesService.samples(null, null, null, null, null, 20, 0).events().get(0);

		assertThat(sample.rule().id()).isEqualTo("950001");
		assertThat(sample.rule().category()).isEqualTo(Category.INJECTION);
		assertThat(sample.geoLocation().country()).isEqualTo("CN");
		assertThat(sample.geoLocation().city()).isEqualTo("Beijing");
	}

	@Test
	void geoLocationIsNullWhenNotStored() {
		when(samplesRepository.findSamples(null, EARLIEST, LATEST, null, null, 20, 0))
				.thenReturn(List.of(entity("e1", null, null)));

		SampleEvent sample = samplesService.samples(null, null, null, null, null, 20, 0).events().get(0);

		assertThat(sample.geoLocation()).isNull();
	}

	private SecurityEvent entity(String eventId, String country, String city) {
		SecurityEvent event = new SecurityEvent();
		event.setEventId(eventId);
		event.setEventTime(Instant.parse("2026-05-20T10:00:00Z"));
		event.setRuleId("950001");
		event.setRuleSeverity(Severity.CRITICAL);
		event.setRuleCategory(Category.INJECTION);
		event.setAction(Action.DENY);
		event.setGeoCountry(country);
		event.setGeoCity(city);
		return event;
	}
}
