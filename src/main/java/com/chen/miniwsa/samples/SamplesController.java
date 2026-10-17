package com.chen.miniwsa.samples;

import java.time.Instant;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.chen.miniwsa.error.BadRequestException;
import com.chen.miniwsa.event.Action;
import com.chen.miniwsa.event.Category;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/v1/events")
@RequiredArgsConstructor
public class SamplesController {

	private static final int MAX_LIMIT = 100;

	private final SamplesService samplesService;

	@GetMapping("/samples")
	public SamplesResponse samples(
			@RequestParam(required = false) Long configId,
			@RequestParam(required = false) Instant from,
			@RequestParam(required = false) Instant to,
			@RequestParam(required = false) Category category,
			@RequestParam(required = false) Action action,
			@RequestParam(defaultValue = "20") int limit,
			@RequestParam(defaultValue = "0") int offset) {
		if (limit < 1 || limit > MAX_LIMIT) {
			throw new BadRequestException("'limit' must be between 1 and " + MAX_LIMIT);
		}
		if (offset < 0) {
			throw new BadRequestException("'offset' must not be negative");
		}
		if (from != null && to != null && !from.isBefore(to)) {
			throw new BadRequestException("'from' must be before 'to'");
		}
		return samplesService.samples(configId, from, to, category, action, limit, offset);
	}
}
