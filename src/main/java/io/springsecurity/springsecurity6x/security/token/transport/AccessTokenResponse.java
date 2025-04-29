package io.springsecurity.springsecurity6x.security.token.transport;

public record AccessTokenResponse(String accessToken, String tokenType, long expiresIn, String refreshToken) {
}

