package io.springsecurity.springsecurity6x.jwt.tokenservice;

import org.springframework.boot.autoconfigure.pulsar.PulsarProperties;
import org.springframework.security.core.Authentication;

import java.util.List;
import java.util.Map;
import java.util.function.Consumer;


public interface TokenService {

    String createAccessToken(Consumer<AccessTokenBuilder> builder);
    String createRefreshToken(Consumer<RefreshTokenBuilder> builder);
    boolean validateAccessToken(String token);
    Authentication getAuthenticationFromAccessToken(String token);
    String refreshAccessToken(String refreshToken);
    void invalidateToken(String refreshToken);


    interface AccessTokenBuilder {
        AccessTokenBuilder username(String username);
        AccessTokenBuilder roles(List<String> roles);
        AccessTokenBuilder claims(Map<String, Object> claims);
        AccessTokenBuilder validity(long millis);
    }

    interface RefreshTokenBuilder {
        RefreshTokenBuilder username(String username);
        RefreshTokenBuilder validity(long millis);
    }
}

