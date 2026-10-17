package com.chen.miniwsa.samples;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import com.chen.miniwsa.TestcontainersConfiguration;
import com.chen.miniwsa.event.SecurityEventRepository;

@SpringBootTest
@AutoConfigureMockMvc
@Import(TestcontainersConfiguration.class)
class SamplesIntegrationTest {

	private static final String FULL_EVENT = """
			{
			  "eventId": "evt-00132",
			  "timestamp": "2026-05-20T14:32:10Z",
			  "configId": 14227,
			  "policyId": "pol_web1",
			  "clientIp": "203.0.113.42",
			  "hostname": "www.example.com",
			  "path": "/api/v1/login",
			  "method": "POST",
			  "statusCode": 403,
			  "userAgent": "Mozilla/5.0",
			  "rule": {
			    "id": "950001",
			    "name": "SQL_INJECTION",
			    "message": "SQL Injection Attack Detected",
			    "severity": "CRITICAL",
			    "category": "INJECTION"
			  },
			  "action": "DENY",
			  "geoLocation": { "country": "CN", "city": "Beijing" },
			  "requestSize": 1024,
			  "responseSize": 256
			}
			""";

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private SecurityEventRepository repository;

	@BeforeEach
	void cleanDatabase() {
		repository.deleteAll();
	}

	@Test
	void returnsEnrichedEventInNestedShape() throws Exception {
		ingest(List.of(FULL_EVENT));

		mockMvc.perform(get("/v1/events/samples"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.total").value(1))
				.andExpect(jsonPath("$.limit").value(20))
				.andExpect(jsonPath("$.offset").value(0))
				.andExpect(jsonPath("$.events[0].eventId").value("evt-00132"))
				.andExpect(jsonPath("$.events[0].timestamp").value("2026-05-20T14:32:10Z"))
				.andExpect(jsonPath("$.events[0].receivedAt").exists())
				.andExpect(jsonPath("$.events[0].rule.id").value("950001"))
				.andExpect(jsonPath("$.events[0].rule.category").value("INJECTION"))
				.andExpect(jsonPath("$.events[0].geoLocation.country").value("CN"))
				.andExpect(jsonPath("$.events[0].attackType").value("SQL/Command Injection"))
				.andExpect(jsonPath("$.events[0].threatScore").value(75));
	}

	@Test
	void sortsNewestFirst() throws Exception {
		ingest(List.of(
				event("old", "2026-05-20T10:00:00Z", 14227, "BOT", "DENY"),
				event("new", "2026-05-20T12:00:00Z", 14227, "BOT", "DENY"),
				event("middle", "2026-05-20T11:00:00Z", 14227, "BOT", "DENY")));

		mockMvc.perform(get("/v1/events/samples"))
				.andExpect(jsonPath("$.events[0].eventId").value("new"))
				.andExpect(jsonPath("$.events[1].eventId").value("middle"))
				.andExpect(jsonPath("$.events[2].eventId").value("old"));
	}

	@Test
	void pagesThroughEventsWithTheSameTimestampWithoutDuplicates() throws Exception {
		// Same timestamp: the id tie-breaker decides the order (later insert first)
		String time = "2026-05-20T10:00:00Z";
		ingest(List.of(
				event("e1", time, 14227, "BOT", "DENY"),
				event("e2", time, 14227, "BOT", "DENY"),
				event("e3", time, 14227, "BOT", "DENY"),
				event("e4", time, 14227, "BOT", "DENY"),
				event("e5", time, 14227, "BOT", "DENY")));

		mockMvc.perform(get("/v1/events/samples").param("limit", "2").param("offset", "0"))
				.andExpect(jsonPath("$.total").value(5))
				.andExpect(jsonPath("$.events[0].eventId").value("e5"))
				.andExpect(jsonPath("$.events[1].eventId").value("e4"));

		mockMvc.perform(get("/v1/events/samples").param("limit", "2").param("offset", "2"))
				.andExpect(jsonPath("$.events[0].eventId").value("e3"))
				.andExpect(jsonPath("$.events[1].eventId").value("e2"));

		mockMvc.perform(get("/v1/events/samples").param("limit", "2").param("offset", "4"))
				.andExpect(jsonPath("$.events.length()").value(1))
				.andExpect(jsonPath("$.events[0].eventId").value("e1"));
	}

	@Test
	void appliesAllFiltersTogether() throws Exception {
		ingest(List.of(
				event("match", "2026-05-20T10:00:00Z", 14227, "BOT", "DENY"),
				event("other-config", "2026-05-20T10:00:00Z", 999, "BOT", "DENY"),
				event("other-category", "2026-05-20T10:00:00Z", 14227, "XSS", "DENY"),
				event("other-action", "2026-05-20T10:00:00Z", 14227, "BOT", "ALERT"),
				event("other-day", "2026-05-21T10:00:00Z", 14227, "BOT", "DENY")));

		mockMvc.perform(get("/v1/events/samples")
				.param("configId", "14227")
				.param("from", "2026-05-20T00:00:00Z")
				.param("to", "2026-05-21T00:00:00Z")
				.param("category", "BOT")
				.param("action", "DENY"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.total").value(1))
				.andExpect(jsonPath("$.events[0].eventId").value("match"));
	}

	@Test
	void limitAbove100Returns400() throws Exception {
		mockMvc.perform(get("/v1/events/samples").param("limit", "101"))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.details[0]").value("'limit' must be between 1 and 100"));
	}

	@Test
	void negativeOffsetReturns400() throws Exception {
		mockMvc.perform(get("/v1/events/samples").param("offset", "-1"))
				.andExpect(status().isBadRequest());
	}

	@Test
	void unknownCategoryReturns400() throws Exception {
		mockMvc.perform(get("/v1/events/samples").param("category", "SQLI"))
				.andExpect(status().isBadRequest());
	}

	private void ingest(List<String> events) throws Exception {
		mockMvc.perform(post("/v1/events/ingest")
				.contentType(MediaType.APPLICATION_JSON)
				.content("[" + String.join(",", events) + "]"))
				.andExpect(status().isCreated());
	}

	private String event(String eventId, String timestamp, long configId, String category, String action) {
		return """
				{
				  "eventId": "%s",
				  "timestamp": "%s",
				  "configId": %d,
				  "clientIp": "10.0.0.1",
				  "hostname": "www.example.com",
				  "path": "/products",
				  "method": "GET",
				  "statusCode": 403,
				  "rule": { "id": "1", "severity": "LOW", "category": "%s" },
				  "action": "%s"
				}
				""".formatted(eventId, timestamp, configId, category, action);
	}
}
