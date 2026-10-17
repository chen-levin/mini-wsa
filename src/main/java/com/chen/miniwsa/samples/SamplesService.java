package com.chen.miniwsa.samples;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.chen.miniwsa.event.Action;
import com.chen.miniwsa.event.Category;
import com.chen.miniwsa.event.SecurityEvent;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class SamplesService {

	// Used when from/to are not given, so the query always has a time range
	private static final Instant EARLIEST = Instant.EPOCH;
	private static final Instant LATEST = Instant.parse("9999-12-31T23:59:59Z");

	private final SamplesRepository samplesRepository;

	@Transactional(readOnly = true)
	public SamplesResponse samples(Long configId, Instant from, Instant to,
			Category category, Action action, int limit, int offset) {
		Instant fromOrEarliest = from != null ? from : EARLIEST;
		Instant toOrLatest = to != null ? to : LATEST;

		List<SampleEvent> events = new ArrayList<>();
		for (SecurityEvent event : samplesRepository.findSamples(
				configId, fromOrEarliest, toOrLatest, category, action, limit, offset)) {
			events.add(toSample(event));
		}

		long total = samplesRepository.countSamples(configId, fromOrEarliest, toOrLatest, category, action);

		return new SamplesResponse(total, limit, offset, events);
	}

	// Rebuilds the nested shape of the original DLR from the flat entity
	private SampleEvent toSample(SecurityEvent event) {
		SampleRule rule = new SampleRule(
				event.getRuleId(),
				event.getRuleName(),
				event.getRuleMessage(),
				event.getRuleSeverity(),
				event.getRuleCategory());

		SampleGeoLocation geoLocation = null;
		if (event.getGeoCountry() != null || event.getGeoCity() != null) {
			geoLocation = new SampleGeoLocation(event.getGeoCountry(), event.getGeoCity());
		}

		return new SampleEvent(
				event.getEventId(),
				event.getEventTime(),
				event.getReceivedAt(),
				event.getConfigId(),
				event.getPolicyId(),
				event.getClientIp(),
				event.getHostname(),
				event.getPath(),
				event.getMethod(),
				event.getStatusCode(),
				event.getUserAgent(),
				rule,
				event.getAction(),
				geoLocation,
				event.getRequestSize(),
				event.getResponseSize(),
				event.getAttackType(),
				event.getThreatScore());
	}
}
