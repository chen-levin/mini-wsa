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
 *  - background events: random IPs, paths and rules, spread over the last few hours
 *  - attack waves: one IP hitting one path many times within a few minutes
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

	// How the events are spread in time: over the last 6 hours, ending now
	private static final Duration TIME_SPAN = Duration.ofHours(6);

	// Roughly this share of events belongs to attack waves
	private static final double WAVE_SHARE = 0.3;
	private static final int MIN_WAVE_SIZE = 20;
	private static final int MAX_WAVE_SIZE = 80;

	private static final long[] CONFIG_IDS = { 14227, 14228, 31001 };
	private static final String[] POLICY_IDS = { "pol_web1", "pol_api1", "pol_shop1" };
	private static final String[] HOSTNAMES = { "www.example.com", "api.example.com", "shop.example.com" };

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

	private static final String[][] LOCATIONS = {
			{ "CN", "Beijing" }, { "RU", "Moscow" }, { "US", "New York" }, { "BR", "Sao Paulo" },
			{ "DE", "Berlin" }, { "IN", "Mumbai" }, { "NL", "Amsterdam" } };

	// One rule per category: id, name, message, two typical severities
	private static final Rule[] RULES = {
			new Rule("950001", "SQL_INJECTION", "SQL Injection Attack Detected", "INJECTION", "CRITICAL", "HIGH"),
			new Rule("941100", "XSS_ATTACK", "Cross-site Scripting Attack Detected", "XSS", "HIGH", "MEDIUM"),
			new Rule("920100", "INVALID_HTTP_REQUEST", "Malformed HTTP Request", "PROTOCOL_VIOLATION", "MEDIUM", "LOW"),
			new Rule("950100", "SENSITIVE_DATA_EXPOSURE", "Sensitive Data in Response", "DATA_LEAKAGE", "CRITICAL", "HIGH"),
			new Rule("999001", "BAD_BOT", "Known Malicious Bot", "BOT", "LOW", "MEDIUM"),
			new Rule("999100", "SLOW_POST_DOS", "Slow POST Denial of Service", "DOS", "HIGH", "CRITICAL"),
			new Rule("999200", "RATE_LIMIT_EXCEEDED", "Rate Limit Exceeded", "RATE_LIMIT", "LOW", "MEDIUM") };

	// Waves use the categories that come in bursts: injection probes, bots, DoS, rate limiting
	private static final Rule[] WAVE_RULES = { RULES[0], RULES[4], RULES[5], RULES[6] };

	private final Random random = new Random();
	private final Instant end = Instant.now().truncatedTo(ChronoUnit.SECONDS);
	private final Instant start = end.minus(TIME_SPAN);
	private int nextEventNumber = 1;

	public static void main(String[] args) throws IOException, InterruptedException {
		int count = args.length > 0 ? Integer.parseInt(args[0]) : DEFAULT_COUNT;

		EventGenerator generator = new EventGenerator();
		List<Event> events = generator.generate(count);

		long waveEvents = events.stream().filter(Event::inWave).count();
		System.out.printf("Generated %d events (%d background, %d in attack waves)%n",
				events.size(), events.size() - waveEvents, waveEvents);

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

	List<Event> generate(int count) {
		List<Event> events = new ArrayList<>();
		while (events.size() < count) {
			if (random.nextDouble() < WAVE_SHARE / averageWaveSize()) {
				int size = Math.min(randomBetween(MIN_WAVE_SIZE, MAX_WAVE_SIZE), count - events.size());
				events.addAll(wave(size));
			} else {
				events.add(backgroundEvent());
			}
		}
		// Oldest first, like a real stream of events
		events.sort(Comparator.comparing(Event::timestamp));
		return events;
	}

	// One attacker IP, one path, one rule, events a few seconds apart
	private List<Event> wave(int size) {
		String ip = "198.51.100." + randomBetween(1, 254);
		String path = pick(WAVE_PATHS);
		Rule rule = pick(WAVE_RULES);
		String[] location = pick(LOCATIONS);
		int site = random.nextInt(CONFIG_IDS.length);
		Instant time = randomTime();

		List<Event> events = new ArrayList<>();
		for (int i = 0; i < size; i++) {
			time = time.plusSeconds(randomBetween(1, 5));
			events.add(event(time, site, ip, path, rule, location, true));
		}
		return events;
	}

	private Event backgroundEvent() {
		// A pool of 200 IPs, so some background IPs repeat naturally
		String ip = "203.0.113." + randomBetween(1, 200);
		return event(randomTime(), random.nextInt(CONFIG_IDS.length), ip, pick(PATHS), pick(RULES), pick(LOCATIONS), false);
	}

	private Event event(Instant time, int site, String ip, String path, Rule rule, String[] location, boolean inWave) {
		String action = randomAction();
		return new Event(
				String.format("evt-%06d", nextEventNumber++),
				time,
				CONFIG_IDS[site],
				POLICY_IDS[site],
				ip,
				HOSTNAMES[site],
				path,
				path.contains("login") ? "POST" : "GET",
				action.equals("DENY") ? 403 : 200,
				pick(USER_AGENTS),
				rule,
				random.nextBoolean() ? rule.severity1() : rule.severity2(),
				action,
				location[0],
				location[1],
				randomBetween(200, 5000),
				action.equals("DENY") ? 0 : randomBetween(500, 20000),
				inWave);
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

	private Instant randomTime() {
		return start.plusSeconds(random.nextLong(TIME_SPAN.toSeconds()));
	}

	private int randomBetween(int min, int max) {
		return min + random.nextInt(max - min + 1);
	}

	private <T> T pick(T[] values) {
		return values[random.nextInt(values.length)];
	}

	private static double averageWaveSize() {
		return (MIN_WAVE_SIZE + MAX_WAVE_SIZE) / 2.0;
	}

	private static String toJsonArray(List<Event> events) {
		StringBuilder json = new StringBuilder("[\n");
		for (int i = 0; i < events.size(); i++) {
			json.append(events.get(i).toJson());
			json.append(i < events.size() - 1 ? ",\n" : "\n");
		}
		return json.append("]\n").toString();
	}

	record Rule(String id, String name, String message, String category, String severity1, String severity2) {
	}

	record Event(String eventId, Instant timestamp, long configId, String policyId, String clientIp,
			String hostname, String path, String method, int statusCode, String userAgent,
			Rule rule, String severity, String action, String country, String city,
			int requestSize, int responseSize, boolean inWave) {

		// One event as one line of JSON, in the shape the ingest API expects
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
					+ "\"severity\":\"" + severity + "\","
					+ "\"category\":\"" + rule.category() + "\"},"
					+ "\"action\":\"" + action + "\","
					+ "\"geoLocation\":{\"country\":\"" + country + "\",\"city\":\"" + city + "\"},"
					+ "\"requestSize\":" + requestSize + ","
					+ "\"responseSize\":" + responseSize
					+ "}";
		}
	}
}
