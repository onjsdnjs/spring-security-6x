package io.springsecurity.springsecurity6x.domain;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ErrorResponse(String timestamp, int status, String error, String message, String path) {
}

