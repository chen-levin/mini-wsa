package com.chen.miniwsa.stats;

public record AttackerRow(String clientIp, Long count, Double avgThreatScore) {
}
