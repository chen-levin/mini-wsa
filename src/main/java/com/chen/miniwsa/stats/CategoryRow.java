package com.chen.miniwsa.stats;

import com.chen.miniwsa.event.Category;

public record CategoryRow(Category category, Long count, Double avgThreatScore) {
}
