package io.springsecurity.springsecurity6x.security.tokenservice;

import org.springframework.security.core.Authentication;

import java.util.List;
import java.util.Map;
import java.util.function.Consumer;


public interface TokenService {

    String createAccessToken(Consumer<TokenBuilder> builder);
    String createRefreshToken(Consumer<TokenBuilder> builder);
    boolean validateAccessToken(String token);
    Authentication getAuthenticationFromAccessToken(String token);
    String refreshAccessToken(String refreshToken);
    void invalidateToken(String refreshToken);


    interface TokenBuilder {
        TokenBuilder username(String username);
        TokenBuilder validity(long validity);
        default TokenBuilder roles(List<String> roles){return this;};
        default TokenBuilder claims(Map<String, Object> claims){return this;};
    }
}

