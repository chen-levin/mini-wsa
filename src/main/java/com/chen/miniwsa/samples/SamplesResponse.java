package com.chen.miniwsa.samples;

import java.util.List;

public record SamplesResponse(
		long total,
		int limit,
		int offset,
		List<SampleEvent> events) {
}
