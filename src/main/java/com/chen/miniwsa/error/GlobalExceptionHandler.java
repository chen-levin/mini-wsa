package com.chen.miniwsa.error;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.springframework.context.MessageSourceResolvable;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.FieldError;
import org.springframework.validation.method.ParameterValidationResult;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.HandlerMethodValidationException;

import tools.jackson.core.JacksonException;

@RestControllerAdvice
public class GlobalExceptionHandler {

	// Bean Validation failed (@NotNull, @Size, @NotEmpty, ...)
	@ExceptionHandler(HandlerMethodValidationException.class)
	@ResponseStatus(HttpStatus.BAD_REQUEST)
	public ErrorResponse handleValidation(HandlerMethodValidationException ex) {
		List<String> details = new ArrayList<>();
		for (ParameterValidationResult result : ex.getParameterValidationResults()) {
			String prefix = result.getContainerIndex() != null ? "[" + result.getContainerIndex() + "]." : "";
			for (MessageSourceResolvable error : result.getResolvableErrors()) {
				if (error instanceof FieldError fieldError) {
					details.add(prefix + fieldError.getField() + ": " + fieldError.getDefaultMessage());
				} else {
					details.add(error.getDefaultMessage());
				}
			}
		}
		Collections.sort(details);
		return new ErrorResponse(400, "Validation failed", details);
	}

	// JSON could not be parsed (bad syntax, unknown enum value, bad timestamp format)
	@ExceptionHandler(HttpMessageNotReadableException.class)
	@ResponseStatus(HttpStatus.BAD_REQUEST)
	public ErrorResponse handleUnreadable(HttpMessageNotReadableException ex) {
		String detail;
		if (ex.getCause() instanceof JacksonException jacksonEx && !jacksonEx.getPath().isEmpty()) {
			detail = fieldPath(jacksonEx) + ": " + firstLine(jacksonEx.getOriginalMessage());
		} else {
			detail = firstLine(ex.getMostSpecificCause().getMessage());
		}
		return new ErrorResponse(400, "Malformed request body", List.of(detail));
	}

	// Builds "[0].rule.severity" from Jackson's path to the bad value
	private String fieldPath(JacksonException ex) {
		StringBuilder path = new StringBuilder();
		for (JacksonException.Reference ref : ex.getPath()) {
			if (ref.getPropertyName() != null) {
				if (!path.isEmpty()) {
					path.append('.');
				}
				path.append(ref.getPropertyName());
			} else {
				path.append('[').append(ref.getIndex()).append(']');
			}
		}
		return path.toString();
	}

	private String firstLine(String message) {
		return message.lines().findFirst().orElse(message);
	}
}
