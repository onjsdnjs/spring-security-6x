package io.springsecurity.springsecurity6x.jwt.tokenservice;

import org.springframework.security.core.Authentication;

import java.util.List;

public interface TokenService {

    String createAccessToken(String username, List<String> roles);

    String createRefreshToken(String username);

    boolean validateAccessToken(String token);

    Authentication getAuthenticationFromAccessToken(String token);

    String refreshAccessToken(String refreshToken);

    void invalidateToken(String refreshToken);

}

