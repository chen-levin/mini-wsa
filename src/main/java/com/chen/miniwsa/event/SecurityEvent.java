package com.chen.miniwsa.event;

import java.time.Instant;

import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
@Table(name = "security_event")
public class SecurityEvent {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	private String eventId;
	private Instant eventTime;
	private Instant receivedAt;
	private Long configId;
	private String policyId;
	private String clientIp;
	private String hostname;
	private String path;
	private String method;
	private Integer statusCode;
	private String userAgent;

	private String ruleId;
	private String ruleName;
	private String ruleMessage;

	@Enumerated(EnumType.STRING)
	private Severity ruleSeverity;

	@Enumerated(EnumType.STRING)
	private Category ruleCategory;

	@Enumerated(EnumType.STRING)
	private Action action;

	private String geoCountry;
	private String geoCity;
	private Long requestSize;
	private Long responseSize;
}
