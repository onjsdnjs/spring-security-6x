package io.springsecurity.springsecurity6x.security.token.parser;

public interface JwtParser {

    ParsedJwt parse(String token);

    boolean isValidAccessToken(String token);

    boolean isValidRefreshToken(String token);
}

