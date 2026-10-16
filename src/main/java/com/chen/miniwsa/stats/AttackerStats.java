package com.chen.miniwsa.stats;

public record AttackerStats(String clientIp, long count, double avgThreatScore) {
}
