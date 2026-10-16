package com.chen.miniwsa.event;

import java.time.Instant;

import org.springframework.data.jpa.repository.JpaRepository;

public interface SecurityEventRepository extends JpaRepository<SecurityEvent, Long> {

	long countByClientIpAndEventTimeBetween(String clientIp, Instant from, Instant to);
}
