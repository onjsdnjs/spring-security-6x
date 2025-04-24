package io.springsecurity.springsecurity6x.security.token.store;

import io.springsecurity.springsecurity6x.security.token.parser.JwtParser;

public interface RefreshTokenStore {

    void store(String refreshToken, String username);

    String getUsername(String refreshToken);

    void remove(String refreshToken);

    JwtParser parser();
}
