package io.springsecurity.springsecurity6x.security.token.store;

public interface RefreshTokenStore{
    void store(String token, String username);
    void remove(String token);
    String getUsername(String refreshToken);
    void blacklist(String token, String username, String reason);
    boolean isBlacklisted(String token);
}
