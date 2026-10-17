package com.chen.miniwsa.samples;

import java.time.Instant;

import com.chen.miniwsa.event.Action;

public record SampleEvent(
		String eventId,
		Instant timestamp,
		Instant receivedAt,
		Long configId,
		String policyId,
		String clientIp,
		String hostname,
		String path,
		String method,
		Integer statusCode,
		String userAgent,
		SampleRule rule,
		Action action,
		SampleGeoLocation geoLocation,
		Long requestSize,
		Long responseSize,
		String attackType,
		Integer threatScore) {
}
