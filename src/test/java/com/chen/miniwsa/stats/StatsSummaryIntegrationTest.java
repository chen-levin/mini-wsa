package com.chen.miniwsa.stats;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.ArrayList;
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
class StatsSummaryIntegrationTest {

	private static final String FROM = "2026-05-20T00:00:00Z";
	private static final String TO = "2026-05-21T00:00:00Z";

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private SecurityEventRepository repository;

	@BeforeEach
	void cleanDatabase() {
		repository.deleteAll();
	}

	@Test
	void summaryForOneConfig() throws Exception {
		ingestSampleEvents();

		mockMvc.perform(get("/v1/stats/summary")
				.param("configId", "14227")
				.param("from", FROM)
				.param("to", TO))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.configId").value(14227))
				.andExpect(jsonPath("$.timeRange.from").value(FROM))
				.andExpect(jsonPath("$.totalEvents").value(4))
				// INJECTION: 75 and 55 -> avg 65.0
				.andExpect(jsonPath("$.byCategory.INJECTION.count").value(2))
				.andExpect(jsonPath("$.byCategory.INJECTION.avgThreatScore").value(65.0))
				// BOT: 10 and 40 -> avg 25.0
				.andExpect(jsonPath("$.byCategory.BOT.count").value(2))
				.andExpect(jsonPath("$.byCategory.BOT.avgThreatScore").value(25.0))
				// No XSS in this config: filled with zero
				.andExpect(jsonPath("$.byCategory.XSS.count").value(0))
				.andExpect(jsonPath("$.byAction.DENY").value(2))
				.andExpect(jsonPath("$.byAction.ALERT").value(1))
				.andExpect(jsonPath("$.byAction.MONITOR").value(1))
				// 1.1.1.1: 75, 55, 10 -> avg 46.7
				.andExpect(jsonPath("$.topAttackers[0].clientIp").value("1.1.1.1"))
				.andExpect(jsonPath("$.topAttackers[0].count").value(3))
				.andExpect(jsonPath("$.topAttackers[0].avgThreatScore").value(46.7))
				.andExpect(jsonPath("$.topAttackers[1].clientIp").value("2.2.2.2"))
				.andExpect(jsonPath("$.topTargetedPaths[0].path").value("/products"))
				.andExpect(jsonPath("$.topTargetedPaths[0].count").value(2));
	}

	@Test
	void summaryWithoutConfigIdIncludesAllConfigs() throws Exception {
		ingestSampleEvents();

		mockMvc.perform(get("/v1/stats/summary")
				.param("from", FROM)
				.param("to", TO))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.configId").doesNotExist())
				.andExpect(jsonPath("$.totalEvents").value(5))
				.andExpect(jsonPath("$.byCategory.XSS.count").value(1));
	}

	@Test
	void topAttackersIsLimitedToTen() throws Exception {
		List<String> events = new ArrayList<>();
		for (int i = 1; i <= 11; i++) {
			events.add(event("2026-05-20T10:00:00Z", 14227, "10.0.0." + i, "/products", "LOW", "BOT", "MONITOR"));
		}
		ingest(events);

		mockMvc.perform(get("/v1/stats/summary")
				.param("from", FROM)
				.param("to", TO))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.totalEvents").value(11))
				.andExpect(jsonPath("$.topAttackers.length()").value(10));
	}

	@Test
	void missingFromReturns400() throws Exception {
		mockMvc.perform(get("/v1/stats/summary")
				.param("to", TO))
				.andExpect(status().isBadRequest());
	}

	@Test
	void fromAfterToReturns400() throws Exception {
		mockMvc.perform(get("/v1/stats/summary")
				.param("from", TO)
				.param("to", FROM))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.details[0]").value("'from' must be before 'to'"));
	}

	// Scores: CRITICAL/HIGH/MEDIUM/LOW = 40/30/20/10, DENY/ALERT/MONITOR = 20/10/0, /login or /admin = +15
	private void ingestSampleEvents() throws Exception {
		ingest(List.of(
				// Exactly at 'from': included
				event("2026-05-20T00:00:00Z", 14227, "1.1.1.1", "/api/v1/login", "CRITICAL", "INJECTION", "DENY"), // 75
				event("2026-05-20T10:01:00Z", 14227, "1.1.1.1", "/admin", "HIGH", "INJECTION", "ALERT"),           // 55
				event("2026-05-20T10:02:00Z", 14227, "1.1.1.1", "/products", "LOW", "BOT", "MONITOR"),             // 10
				event("2026-05-20T10:03:00Z", 14227, "2.2.2.2", "/products", "MEDIUM", "BOT", "DENY"),             // 40
				// Another config
				event("2026-05-20T10:04:00Z", 999, "3.3.3.3", "/x", "MEDIUM", "XSS", "DENY"),                     // 40
				// Exactly at 'to': excluded
				event("2026-05-21T00:00:00Z", 14227, "1.1.1.1", "/products", "LOW", "BOT", "MONITOR")));
	}

	private void ingest(List<String> events) throws Exception {
		mockMvc.perform(post("/v1/events/ingest")
				.contentType(MediaType.APPLICATION_JSON)
				.content("[" + String.join(",", events) + "]"))
				.andExpect(status().isCreated());
	}

	private String event(String timestamp, long configId, String clientIp, String path,
			String severity, String category, String action) {
		return """
				{
				  "eventId": "evt",
				  "timestamp": "%s",
				  "configId": %d,
				  "clientIp": "%s",
				  "hostname": "www.example.com",
				  "path": "%s",
				  "method": "GET",
				  "statusCode": 403,
				  "rule": { "id": "1", "severity": "%s", "category": "%s" },
				  "action": "%s"
				}
				""".formatted(timestamp, configId, clientIp, path, severity, category, action);
	}
}
