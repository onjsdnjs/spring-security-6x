package io.springsecurity.springsecurity6x.security.token.service;

import org.springframework.security.core.Authentication;

import java.util.List;
import java.util.Map;
import java.util.function.Consumer;


public interface TokenService {

    String ACCESS_TOKEN = "accessToken";
    String REFRESH_TOKEN = "refreshToken";

    String createAccessToken(Consumer<TokenBuilder> builder);

    String createRefreshToken(Consumer<TokenBuilder> builder);

    boolean validateAccessToken(String accessToken);

    boolean validateRefreshToken(String refreshToken);

    Authentication getAuthenticationFromToken(String token);

    Map<String, String> refreshTokens(String refreshToken);

    void invalidateToken(String refreshToken);

    boolean shouldRotateRefreshToken(String refreshToken);

    String createAccessTokenFromRefresh(String refreshToken);

    interface TokenBuilder {

        TokenBuilder username(String username);

        TokenBuilder validity(long validity);

        default TokenBuilder roles(List<String> roles){return this;};

        default TokenBuilder claims(Map<String, Object> claims){return this;};
    }
}

