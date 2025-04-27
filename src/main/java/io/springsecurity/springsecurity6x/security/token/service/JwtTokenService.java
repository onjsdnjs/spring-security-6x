package io.springsecurity.springsecurity6x.security.token.service;

import io.springsecurity.springsecurity6x.security.converter.AuthenticationConverter;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.store.RefreshTokenStore;
import org.springframework.context.ApplicationContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtException;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public abstract class JwtTokenService implements TokenService {


    private final RefreshTokenStore refreshTokenStore;
    private final AuthenticationConverter authenticationConverter;
    private final AuthContextProperties properties;

    public JwtTokenService(RefreshTokenStore refreshTokenStore, AuthenticationConverter authenticationConverter, ApplicationContext applicationContext) {
        this.refreshTokenStore = refreshTokenStore;
        this.authenticationConverter = authenticationConverter;
        properties = applicationContext.getBean(AuthContextProperties.class);
    }

    @Override
    public Map<String, String> refreshTokens(String refreshToken) {
        // 1) 스토어 조회 & 검증
        String username = refreshTokenStore.getUsername(refreshToken);
        if (username == null) {
            throw new JwtException("Invalid or expired refresh token");
        }

        // 2) 회전 필요 여부 판단
        boolean rotate = shouldRotateRefreshToken(refreshToken);
        String usedRefresh = refreshToken;

        if(rotate){
            // 2-1) 회전: 기존 토큰 삭제 → 새 토큰 발급 & 저장
            refreshTokenStore.remove(refreshToken);
            // 3) 새 리프레시 토큰 발급 & 저장
            String newRefreshToken = createRefreshToken(builder -> builder
                    .username(username)
                    .roles(authenticationConverter.getRoles(refreshToken))
                    .validity(properties.getExternal().getRefreshTokenValidity())
            );
            refreshTokenStore.store(newRefreshToken, username);
            usedRefresh = newRefreshToken;

        }
        // 4) 새 액세스 토큰 발급
        String newAccessToken = createAccessTokenFromRefresh(usedRefresh);
        // 5) 클라이언트에 둘 다 반환 (또는 쿠키 설정)
        return Map.of(TokenService.ACCESS_TOKEN, newAccessToken, TokenService.REFRESH_TOKEN, usedRefresh);
    }

    @Override
    public void invalidateToken(String refreshToken) {
        refreshTokenStore.remove(refreshToken);
    }

    public Authentication getAuthenticationFromToken(String token) {
        return authenticationConverter.getAuthentication(token);
    }

    public RefreshTokenStore refreshTokenStore() {
        return refreshTokenStore;
    }

    public AuthContextProperties properties() {
        return properties;
    }

    public AuthenticationConverter authenticationConverter() {
        return authenticationConverter;
    }

    static class DefaultTokenBuilder implements TokenBuilder {
        private String              username;
        private List<String>        roles   = Collections.emptyList();
        private Map<String, Object> claims  = new HashMap<>();
        private long                validity;

        @Override
        public TokenBuilder username(String username) {
            this.username = username;
            return this;
        }

        @Override
        public TokenBuilder roles(List<String> roles) {
            this.roles = roles;
            return this;
        }

        @Override
        public TokenBuilder claims(Map<String, Object> claims) {
            this.claims.putAll(claims);
            return this;
        }

        @Override
        public TokenBuilder validity(long millis) {
            this.validity = millis;
            return this;
        }

        public String getUsername() {
            return username;
        }

        public List<String> getRoles() {
            return roles;
        }

        public Map<String, Object> getClaims() {
            return claims;
        }

        public long getValidity() {
            return validity;
        }
    }
}

