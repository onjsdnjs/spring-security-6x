package io.springsecurity.springsecurity6x.security.handler;

import lombok.Data;
import org.springframework.security.core.Authentication;

import java.util.HashMap;
import java.util.Map;

@Data
public class AuthSuccessContext {
    private final String accessToken;
    private final String refreshToken;
    private final String redirectUrl;
    private final Authentication authentication;
    private final Map<String, Object> additionalData = new HashMap<>();
}
