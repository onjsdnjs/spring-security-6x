package io.springsecurity.springsecurity6x.security.http;

// io.springsecurity.springsecurity6x.security.http.AuthResponseWriter.java (New interface)

import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

public interface AuthResponseWriter {
    void writeSuccessResponse(HttpServletResponse response, Object data) throws IOException;
    void writeErrorResponse(HttpServletResponse response, int status, String errorCode, String errorMessage, String path) throws IOException;
}
