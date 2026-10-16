package com.chen.miniwsa.stats;

import java.time.Instant;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.chen.miniwsa.error.BadRequestException;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/v1/stats")
@RequiredArgsConstructor
public class StatsController {

	private final StatsService statsService;

	@GetMapping("/summary")
	public StatsSummaryResponse summary(
			@RequestParam(required = false) Long configId,
			@RequestParam Instant from,
			@RequestParam Instant to) {
		if (!from.isBefore(to)) {
			throw new BadRequestException("'from' must be before 'to'");
		}
		return statsService.summary(configId, from, to);
	}
}
