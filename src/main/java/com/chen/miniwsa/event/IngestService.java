package com.chen.miniwsa.event;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.chen.miniwsa.enrichment.AttackTypeClassifier;
import com.chen.miniwsa.enrichment.ThreatScoreCalculator;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class IngestService {

	private static final Duration REPEAT_OFFENDER_WINDOW = Duration.ofMinutes(10);

	private final SecurityEventRepository repository;

	@Transactional
	public int ingest(List<EventRequest> requests) {
		Instant receivedAt = Instant.now();

		// Saved one by one, so later events in the same batch count earlier ones as recent
		for (EventRequest request : requests) {
			SecurityEvent event = toEntity(request, receivedAt);
			enrich(event);
			repository.save(event);
		}

		return requests.size();
	}

	private void enrich(SecurityEvent event) {
		event.setAttackType(AttackTypeClassifier.classify(event.getRuleCategory()));

		long recentEventsFromSameIp = repository.countByClientIpAndEventTimeBetween(
				event.getClientIp(),
				event.getEventTime().minus(REPEAT_OFFENDER_WINDOW),
				event.getEventTime());

		event.setThreatScore(ThreatScoreCalculator.calculate(
				event.getRuleSeverity(),
				event.getAction(),
				event.getPath(),
				recentEventsFromSameIp));
	}

	private SecurityEvent toEntity(EventRequest request, Instant receivedAt) {
		SecurityEvent event = new SecurityEvent();
		event.setEventId(request.eventId());
		event.setEventTime(request.timestamp());
		event.setReceivedAt(receivedAt);
		event.setConfigId(request.configId());
		event.setPolicyId(request.policyId());
		event.setClientIp(request.clientIp());
		event.setHostname(request.hostname());
		event.setPath(request.path());
		event.setMethod(request.method());
		event.setStatusCode(request.statusCode());
		event.setUserAgent(request.userAgent());

		event.setRuleId(request.rule().id());
		event.setRuleName(request.rule().name());
		event.setRuleMessage(request.rule().message());
		event.setRuleSeverity(request.rule().severity());
		event.setRuleCategory(request.rule().category());

		event.setAction(request.action());

		if (request.geoLocation() != null) {
			event.setGeoCountry(request.geoLocation().country());
			event.setGeoCity(request.geoLocation().city());
		}

		event.setRequestSize(request.requestSize());
		event.setResponseSize(request.responseSize());
		return event;
	}
}
