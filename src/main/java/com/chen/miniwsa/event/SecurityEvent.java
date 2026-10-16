package com.chen.miniwsa.event;

import java.time.Instant;

import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
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

	public Long getId() {
		return id;
	}

	public String getEventId() {
		return eventId;
	}

	public void setEventId(String eventId) {
		this.eventId = eventId;
	}

	public Instant getEventTime() {
		return eventTime;
	}

	public void setEventTime(Instant eventTime) {
		this.eventTime = eventTime;
	}

	public Instant getReceivedAt() {
		return receivedAt;
	}

	public void setReceivedAt(Instant receivedAt) {
		this.receivedAt = receivedAt;
	}

	public Long getConfigId() {
		return configId;
	}

	public void setConfigId(Long configId) {
		this.configId = configId;
	}

	public String getPolicyId() {
		return policyId;
	}

	public void setPolicyId(String policyId) {
		this.policyId = policyId;
	}

	public String getClientIp() {
		return clientIp;
	}

	public void setClientIp(String clientIp) {
		this.clientIp = clientIp;
	}

	public String getHostname() {
		return hostname;
	}

	public void setHostname(String hostname) {
		this.hostname = hostname;
	}

	public String getPath() {
		return path;
	}

	public void setPath(String path) {
		this.path = path;
	}

	public String getMethod() {
		return method;
	}

	public void setMethod(String method) {
		this.method = method;
	}

	public Integer getStatusCode() {
		return statusCode;
	}

	public void setStatusCode(Integer statusCode) {
		this.statusCode = statusCode;
	}

	public String getUserAgent() {
		return userAgent;
	}

	public void setUserAgent(String userAgent) {
		this.userAgent = userAgent;
	}

	public String getRuleId() {
		return ruleId;
	}

	public void setRuleId(String ruleId) {
		this.ruleId = ruleId;
	}

	public String getRuleName() {
		return ruleName;
	}

	public void setRuleName(String ruleName) {
		this.ruleName = ruleName;
	}

	public String getRuleMessage() {
		return ruleMessage;
	}

	public void setRuleMessage(String ruleMessage) {
		this.ruleMessage = ruleMessage;
	}

	public Severity getRuleSeverity() {
		return ruleSeverity;
	}

	public void setRuleSeverity(Severity ruleSeverity) {
		this.ruleSeverity = ruleSeverity;
	}

	public Category getRuleCategory() {
		return ruleCategory;
	}

	public void setRuleCategory(Category ruleCategory) {
		this.ruleCategory = ruleCategory;
	}

	public Action getAction() {
		return action;
	}

	public void setAction(Action action) {
		this.action = action;
	}

	public String getGeoCountry() {
		return geoCountry;
	}

	public void setGeoCountry(String geoCountry) {
		this.geoCountry = geoCountry;
	}

	public String getGeoCity() {
		return geoCity;
	}

	public void setGeoCity(String geoCity) {
		this.geoCity = geoCity;
	}

	public Long getRequestSize() {
		return requestSize;
	}

	public void setRequestSize(Long requestSize) {
		this.requestSize = requestSize;
	}

	public Long getResponseSize() {
		return responseSize;
	}

	public void setResponseSize(Long responseSize) {
		this.responseSize = responseSize;
	}
}
