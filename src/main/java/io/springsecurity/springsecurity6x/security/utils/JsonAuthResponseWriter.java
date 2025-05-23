package io.springsecurity.springsecurity6x.security.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Component
public class JsonAuthResponseWriter implements AuthResponseWriter {
    private final ObjectMapper objectMapper;

    public JsonAuthResponseWriter(ObjectMapper objectMapper) {
        this.objectMapper = Objects.requireNonNull(objectMapper, "ObjectMapper cannot be null");
    }

    @Override
    public void writeSuccessResponse(HttpServletResponse response, Object data, int status) throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        objectMapper.writeValue(response.getWriter(), data);
    }

    @Override
    public void writeErrorResponse(HttpServletResponse response, int status, String errorCode, String errorMessage, String path) throws IOException {

        writeError(response, status, errorCode, errorMessage, path, new HashMap<>());
    }

    @Override
    public void writeErrorResponse(HttpServletResponse response, int status, String errorCode, String errorMessage, String path, Map<String, Object> errorDetails) throws IOException{
        writeError(response, status, errorCode, errorMessage, path, errorDetails);
    }

    private void writeError(HttpServletResponse response, int status, String path, String errorCode, String errorMessage, Map<String, Object> errorDetails) throws IOException {


        errorDetails.put("timestamp", Instant.now().toString());
        errorDetails.put("status", status);
        errorDetails.put("error", errorCode);
        errorDetails.put("message", errorMessage);

        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        if (path != null) {
            errorDetails.put("path", path);
        }
        objectMapper.writeValue(response.getWriter(), errorDetails);
    }
}
