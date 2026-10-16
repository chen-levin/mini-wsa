package com.chen.miniwsa.event;

import java.time.Instant;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.PositiveOrZero;
import jakarta.validation.constraints.Size;

public record EventRequest(
		@NotBlank @Size(max = 100) String eventId,
		@NotNull Instant timestamp,
		@NotNull Long configId,
		@Size(max = 100) String policyId,
		@NotBlank @Size(max = 45) String clientIp,
		@NotBlank @Size(max = 255) String hostname,
		@NotBlank String path,
		@NotBlank @Size(max = 10) String method,
		@NotNull @Min(100) @Max(599) Integer statusCode,
		String userAgent,
		@NotNull @Valid RuleRequest rule,
		@NotNull Action action,
		@Valid GeoLocationRequest geoLocation,
		@PositiveOrZero Long requestSize,
		@PositiveOrZero Long responseSize) {
}
