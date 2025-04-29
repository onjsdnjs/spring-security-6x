package io.springsecurity.springsecurity6x.security.token.transport;

public record TokenResponse(String accessToken, String tokenType, long expiresIn, String refreshToken) {
}

