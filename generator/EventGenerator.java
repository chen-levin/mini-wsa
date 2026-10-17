import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Random;

/**
 * Generates random security events (DLRs) for the Mini WSA ingest API.
 *
 * Mix of:
 *  - attack waves: one IP hitting one path 50 times, 5 seconds apart
 *  - background events: random IPs, paths and rules
 * All events fall within the last 6 hours.
 *
 * Run (no build needed, Java 21):
 *   java generator/EventGenerator.java [count] [outputFile]        write to a file
 *   java generator/EventGenerator.java [count] --send [baseUrl]    post to the ingest API
 *
 *   java generator/EventGenerator.java 10000 events.json
 *   java generator/EventGenerator.java 10000 --send
 */
public class EventGenerator {

	private static final int DEFAULT_COUNT = 10_000;
	private static final String DEFAULT_OUTPUT = "events.json";
	private static final String DEFAULT_BASE_URL = "http://localhost:8080";
	private static final int BATCH_SIZE = 500;

	// All events fall within the last 6 hours
	private static final Duration TIME_SPAN = Duration.ofHours(6);

	// 30% of events belong to attack waves; every wave is 50 events, 5 seconds apart
	private static final int WAVE_PERCENT = 30;
	private static final int WAVE_SIZE = 50;
	private static final int SECONDS_BETWEEN_WAVE_EVENTS = 5;
	private static final Duration WAVE_DURATION = Duration.ofSeconds((long) WAVE_SIZE * SECONDS_BETWEEN_WAVE_EVENTS);

	// Three customer websites, each with its own config
	private static final Site[] SITES = {
			new Site(14227, "pol_web1", "www.example.com"),
			new Site(14228, "pol_api1", "api.example.com"),
			new Site(31001, "pol_shop1", "shop.example.com") };

	private static final String[] PATHS = {
			"/", "/login", "/admin", "/api/v1/login", "/api/v1/users", "/api/v1/orders",
			"/search", "/products", "/checkout", "/wp-admin", "/static/app.js" };
	private static final String[] WAVE_PATHS = { "/login", "/api/v1/login", "/admin", "/search" };

	private static final String[] USER_AGENTS = {
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5)",
			"curl/8.4.0",
			"python-requests/2.31.0",
			"sqlmap/1.7",
			"Go-http-client/1.1" };

	private static final GeoLocation[] LOCATIONS = {
			new GeoLocation("CN", "Beijing"), new GeoLocation("RU", "Moscow"),
			new GeoLocation("US", "New York"), new GeoLocation("BR", "Sao Paulo"),
			new GeoLocation("DE", "Berlin"), new GeoLocation("IN", "Mumbai"),
			new GeoLocation("NL", "Amsterdam") };

	// One rule per category
	private static final Rule[] RULES = {
			new Rule("950001", "SQL_INJECTION", "SQL Injection Attack Detected", "CRITICAL", "INJECTION"),
			new Rule("941100", "XSS_ATTACK", "Cross-site Scripting Attack Detected", "HIGH", "XSS"),
			new Rule("920100", "INVALID_HTTP_REQUEST", "Malformed HTTP Request", "MEDIUM", "PROTOCOL_VIOLATION"),
			new Rule("950100", "SENSITIVE_DATA_EXPOSURE", "Sensitive Data in Response", "CRITICAL", "DATA_LEAKAGE"),
			new Rule("999001", "BAD_BOT", "Known Malicious Bot", "LOW", "BOT"),
			new Rule("999100", "SLOW_POST_DOS", "Slow POST Denial of Service", "HIGH", "DOS"),
			new Rule("999200", "RATE_LIMIT_EXCEEDED", "Rate Limit Exceeded", "LOW", "RATE_LIMIT") };

	// Waves use the categories that come in bursts: injection probes, bots, DoS, rate limiting
	private static final Rule[] WAVE_RULES = { RULES[0], RULES[4], RULES[5], RULES[6] };

	private final Random random = new Random();
	private final Instant end = Instant.now().truncatedTo(ChronoUnit.SECONDS);
	private final Instant start = end.minus(TIME_SPAN);
	private int nextEventNumber = 1;

	public static void main(String[] args) throws IOException, InterruptedException {
		int count = args.length > 0 ? Integer.parseInt(args[0]) : DEFAULT_COUNT;

		// e.g. 10000 events: 30% = 3000 wave events = 60 waves of 50, plus 7000 background events
		int waveCount = count * WAVE_PERCENT / 100 / WAVE_SIZE;
		int backgroundCount = count - waveCount * WAVE_SIZE;

		EventGenerator generator = new EventGenerator();
		List<Event> events = generator.generate(waveCount, backgroundCount);
		System.out.printf("Generated %d events: %d waves of %d events + %d background events%n",
				events.size(), waveCount, WAVE_SIZE, backgroundCount);

		if (args.length > 1 && args[1].equals("--send")) {
			String baseUrl = args.length > 2 ? args[2] : DEFAULT_BASE_URL;
			send(events, baseUrl);
		} else {
			Path output = Path.of(args.length > 1 ? args[1] : DEFAULT_OUTPUT);
			Files.writeString(output, toJsonArray(events));
			System.out.println("Written to " + output);
		}
	}

	// Posts the events to the ingest API in batches, oldest first
	private static void send(List<Event> events, String baseUrl) throws IOException, InterruptedException {
		HttpClient client = HttpClient.newHttpClient();
		URI ingestUri = URI.create(baseUrl + "/v1/events/ingest");

		for (int from = 0; from < events.size(); from += BATCH_SIZE) {
			int to = Math.min(from + BATCH_SIZE, events.size());
			HttpRequest request = HttpRequest.newBuilder(ingestUri)
					.header("Content-Type", "application/json")
					.POST(HttpRequest.BodyPublishers.ofString(toJsonArray(events.subList(from, to))))
					.build();

			HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
			if (response.statusCode() != 201) {
				System.out.println("Failed with HTTP " + response.statusCode() + ": " + response.body());
				System.exit(1);
			}
			System.out.printf("Sent %d/%d%n", to, events.size());
		}
		System.out.println("Done: all events ingested at " + ingestUri);
	}

	List<Event> generate(int waveCount, int backgroundCount) {
		List<Event> events = new ArrayList<>();
		for (int i = 0; i < waveCount; i++) {
			events.addAll(wave());
		}
		for (int i = 0; i < backgroundCount; i++) {
			events.add(backgroundEvent());
		}
		// Oldest first, like a real stream of events
		events.sort(Comparator.comparing(Event::timestamp));
		return events;
	}

	// One attacker: same IP, path, rule, location and site for all 50 events, 5 seconds apart
	private List<Event> wave() {
		String ip = "198.51.100." + randomBetween(1, 254);
		String path = pick(WAVE_PATHS);
		Rule rule = pick(WAVE_RULES);
		GeoLocation location = pick(LOCATIONS);
		Site site = pick(SITES);

		// The whole wave must end before now, so it starts at least WAVE_DURATION before the end
		Instant waveStart = randomTimeBetween(start, end.minus(WAVE_DURATION));

		List<Event> events = new ArrayList<>();
		for (int i = 0; i < WAVE_SIZE; i++) {
			Instant time = waveStart.plusSeconds((long) i * SECONDS_BETWEEN_WAVE_EVENTS);
			events.add(event(time, site, ip, path, rule, location));
		}
		return events;
	}

	// Random everything; a pool of 200 IPs, so some background IPs repeat naturally
	private Event backgroundEvent() {
		String ip = "203.0.113." + randomBetween(1, 200);
		return event(randomTimeBetween(start, end), pick(SITES), ip, pick(PATHS), pick(RULES), pick(LOCATIONS));
	}

	private Event event(Instant time, Site site, String ip, String path, Rule rule, GeoLocation location) {
		String action = randomAction();
		return new Event(
				String.format("evt-%06d", nextEventNumber++),
				time,
				site.configId(),
				site.policyId(),
				ip,
				site.hostname(),
				path,
				path.contains("login") ? "POST" : "GET",
				action.equals("DENY") ? 403 : 200,
				pick(USER_AGENTS),
				rule,
				action,
				location,
				randomBetween(200, 5000),
				action.equals("DENY") ? 0 : randomBetween(500, 20000));
	}

	// DENY 50%, ALERT 30%, MONITOR 20%
	private String randomAction() {
		double r = random.nextDouble();
		if (r < 0.5) {
			return "DENY";
		}
		if (r < 0.8) {
			return "ALERT";
		}
		return "MONITOR";
	}

	private Instant randomTimeBetween(Instant from, Instant to) {
		return from.plusSeconds(random.nextLong(Duration.between(from, to).toSeconds()));
	}

	private int randomBetween(int min, int max) {
		return min + random.nextInt(max - min + 1);
	}

	private <T> T pick(T[] values) {
		return values[random.nextInt(values.length)];
	}

	private static String toJsonArray(List<Event> events) {
		StringBuilder json = new StringBuilder("[\n");
		for (int i = 0; i < events.size(); i++) {
			json.append(events.get(i).toJson());
			json.append(i < events.size() - 1 ? ",\n" : "\n");
		}
		return json.append("]\n").toString();
	}

	record Site(long configId, String policyId, String hostname) {
	}

	record Rule(String id, String name, String message, String severity, String category) {
	}

	record GeoLocation(String country, String city) {
	}

	// Same fields, same order and same nesting as the JSON the ingest API expects
	record Event(String eventId, Instant timestamp, long configId, String policyId, String clientIp,
			String hostname, String path, String method, int statusCode, String userAgent,
			Rule rule, String action, GeoLocation geoLocation, int requestSize, int responseSize) {

		// One event as one line of JSON
		String toJson() {
			return "{"
					+ "\"eventId\":\"" + eventId + "\","
					+ "\"timestamp\":\"" + timestamp + "\","
					+ "\"configId\":" + configId + ","
					+ "\"policyId\":\"" + policyId + "\","
					+ "\"clientIp\":\"" + clientIp + "\","
					+ "\"hostname\":\"" + hostname + "\","
					+ "\"path\":\"" + path + "\","
					+ "\"method\":\"" + method + "\","
					+ "\"statusCode\":" + statusCode + ","
					+ "\"userAgent\":\"" + userAgent + "\","
					+ "\"rule\":{"
					+ "\"id\":\"" + rule.id() + "\","
					+ "\"name\":\"" + rule.name() + "\","
					+ "\"message\":\"" + rule.message() + "\","
					+ "\"severity\":\"" + rule.severity() + "\","
					+ "\"category\":\"" + rule.category() + "\"},"
					+ "\"action\":\"" + action + "\","
					+ "\"geoLocation\":{"
					+ "\"country\":\"" + geoLocation.country() + "\","
					+ "\"city\":\"" + geoLocation.city() + "\"},"
					+ "\"requestSize\":" + requestSize + ","
					+ "\"responseSize\":" + responseSize
					+ "}";
		}
	}
}
