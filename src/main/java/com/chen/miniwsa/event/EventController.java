package com.chen.miniwsa.event;

import java.util.List;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/events")
public class EventController {

	private final IngestService ingestService;

	public EventController(IngestService ingestService) {
		this.ingestService = ingestService;
	}

	@PostMapping("/ingest")
	@ResponseStatus(HttpStatus.CREATED)
	public IngestResponse ingest(@RequestBody @NotEmpty List<@Valid EventRequest> events) {
		int count = ingestService.ingest(events);
		return new IngestResponse(count);
	}
}
