package com.chen.miniwsa.event;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record RuleRequest(
		@NotBlank @Size(max = 50) String id,
		@Size(max = 100) String name,
		String message,
		@NotNull Severity severity,
		@NotNull Category category) {
}
