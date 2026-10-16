package com.chen.miniwsa.event;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import com.chen.miniwsa.TestcontainersConfiguration;

@SpringBootTest
@AutoConfigureMockMvc
@Import(TestcontainersConfiguration.class)
class EventIngestIntegrationTest {

	private static final String VALID_EVENT = """
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
	void singleEventIsStored() throws Exception {
		mockMvc.perform(post("/v1/events/ingest")
				.contentType(MediaType.APPLICATION_JSON)
				.content(VALID_EVENT))
				.andExpect(status().isCreated())
				.andExpect(jsonPath("$.ingested").value(1));

		assertThat(repository.count()).isEqualTo(1);
		SecurityEvent saved = repository.findAll().get(0);
		assertThat(saved.getEventId()).isEqualTo("evt-00132");
		assertThat(saved.getRuleCategory()).isEqualTo(Category.INJECTION);
		assertThat(saved.getGeoCountry()).isEqualTo("CN");
		assertThat(saved.getReceivedAt()).isNotNull();
	}

	@Test
	void arrayOfEventsIsStored() throws Exception {
		mockMvc.perform(post("/v1/events/ingest")
				.contentType(MediaType.APPLICATION_JSON)
				.content("[" + VALID_EVENT + "," + VALID_EVENT + "]"))
				.andExpect(status().isCreated())
				.andExpect(jsonPath("$.ingested").value(2));

		assertThat(repository.count()).isEqualTo(2);
	}

	@Test
	void missingFieldReturns400WithDetails() throws Exception {
		String noSeverity = VALID_EVENT.replace("\"severity\": \"CRITICAL\",", "");

		mockMvc.perform(post("/v1/events/ingest")
				.contentType(MediaType.APPLICATION_JSON)
				.content(noSeverity))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.details[0]").value("[0].rule.severity: must not be null"));

		assertThat(repository.count()).isZero();
	}

	@Test
	void unknownEnumValueReturns400() throws Exception {
		String badAction = VALID_EVENT.replace("\"DENY\"", "\"BLOCK\"");

		mockMvc.perform(post("/v1/events/ingest")
				.contentType(MediaType.APPLICATION_JSON)
				.content(badAction))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.details[0]").value(startsWith("[0].action:")));

		assertThat(repository.count()).isZero();
	}

	@Test
	void emptyArrayReturns400() throws Exception {
		mockMvc.perform(post("/v1/events/ingest")
				.contentType(MediaType.APPLICATION_JSON)
				.content("[]"))
				.andExpect(status().isBadRequest());
	}
}
