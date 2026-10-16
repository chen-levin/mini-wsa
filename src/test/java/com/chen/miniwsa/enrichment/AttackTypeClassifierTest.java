package com.chen.miniwsa.enrichment;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import com.chen.miniwsa.event.Category;

class AttackTypeClassifierTest {

	@Test
	void mapsEveryCategoryToItsAttackType() {
		assertThat(AttackTypeClassifier.classify(Category.INJECTION)).isEqualTo("SQL/Command Injection");
		assertThat(AttackTypeClassifier.classify(Category.XSS)).isEqualTo("Cross-Site Scripting");
		assertThat(AttackTypeClassifier.classify(Category.PROTOCOL_VIOLATION)).isEqualTo("Protocol Anomaly");
		assertThat(AttackTypeClassifier.classify(Category.DATA_LEAKAGE)).isEqualTo("Data Exfiltration");
		assertThat(AttackTypeClassifier.classify(Category.BOT)).isEqualTo("Bot Activity");
		assertThat(AttackTypeClassifier.classify(Category.DOS)).isEqualTo("Denial of Service");
		assertThat(AttackTypeClassifier.classify(Category.RATE_LIMIT)).isEqualTo("Rate Limiting");
	}
}
