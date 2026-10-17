package com.chen.miniwsa.samples;

import com.chen.miniwsa.event.Category;
import com.chen.miniwsa.event.Severity;

public record SampleRule(
		String id,
		String name,
		String message,
		Severity severity,
		Category category) {
}
