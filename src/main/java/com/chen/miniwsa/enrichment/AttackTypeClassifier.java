package com.chen.miniwsa.enrichment;

import com.chen.miniwsa.event.Category;

public class AttackTypeClassifier {

	public static String classify(Category category) {
		return switch (category) {
			case INJECTION -> "SQL/Command Injection";
			case XSS -> "Cross-Site Scripting";
			case PROTOCOL_VIOLATION -> "Protocol Anomaly";
			case DATA_LEAKAGE -> "Data Exfiltration";
			case BOT -> "Bot Activity";
			case DOS -> "Denial of Service";
			case RATE_LIMIT -> "Rate Limiting";
		};
	}
}
