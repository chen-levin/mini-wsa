package com.chen.miniwsa.error;

import java.util.List;

public record ErrorResponse(int status, String error, List<String> details) {
}
