package io.springsecurity.springsecurity6x.security.http;

import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

public interface AuthResponseWriter {
    void writeSuccessResponse(HttpServletResponse response, Object data, int code) throws IOException;
    void writeErrorResponse(HttpServletResponse response, int status, String errorCode, String errorMessage, String path) throws IOException;
}
