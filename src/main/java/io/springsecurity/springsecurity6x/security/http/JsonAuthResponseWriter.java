package io.springsecurity.springsecurity6x.security.http;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;

import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

public class JsonAuthResponseWriter implements AuthResponseWriter {
    private final ObjectMapper objectMapper;

    public JsonAuthResponseWriter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public void writeSuccessResponse(HttpServletResponse response, Object data) throws IOException {
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        objectMapper.writeValue(response.getWriter(), data);
    }

    @Override
    public void writeErrorResponse(HttpServletResponse response, int status, String errorCode, String errorMessage, String path) throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        Map<String, Object> errorBody = new HashMap<>();
        errorBody.put("timestamp", Instant.now().toString());
        errorBody.put("status", status);
        errorBody.put("error", errorCode);
        errorBody.put("message", errorMessage);
        if (path != null) {
            errorBody.put("path", path);
        }
        objectMapper.writeValue(response.getWriter(), errorBody);
    }
}
