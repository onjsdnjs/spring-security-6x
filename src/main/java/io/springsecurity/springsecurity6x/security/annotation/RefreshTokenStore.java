package io.springsecurity.springsecurity6x.security.annotation;

public interface RefreshTokenStore {
    void store(String refreshToken, String username);
    String getUsername(String refreshToken);
    void remove(String refreshToken);
}
