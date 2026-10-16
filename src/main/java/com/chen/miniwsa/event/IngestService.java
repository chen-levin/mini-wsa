package com.chen.miniwsa.event;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class IngestService {

	private final SecurityEventRepository repository;

	public IngestService(SecurityEventRepository repository) {
		this.repository = repository;
	}

	@Transactional
	public int ingest(List<EventRequest> requests) {
		Instant receivedAt = Instant.now();

		List<SecurityEvent> events = new ArrayList<>();
		for (EventRequest request : requests) {
			events.add(toEntity(request, receivedAt));
		}

		repository.saveAll(events);
		return events.size();
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
