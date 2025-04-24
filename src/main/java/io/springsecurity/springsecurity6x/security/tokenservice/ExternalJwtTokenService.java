package io.springsecurity.springsecurity6x.security.tokenservice;

import io.jsonwebtoken.Jwts;
import io.springsecurity.springsecurity6x.security.annotation.RefreshTokenStore;
import io.springsecurity.springsecurity6x.security.configurer.state.JwtStateStrategy;
import io.springsecurity.springsecurity6x.security.converter.AuthenticationConverter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtException;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.*;
import java.util.function.Consumer;

/**
 * 외부 모드용 토큰 서비스:
 *  - 액세스·리프레시 키는 생성자에서 주입
 *  - 리프레시 토큰 보관/만료 관리는 RefreshTokenStore 에 위임
 *  - JWT → Authentication 변환은 AuthenticationConverter 에 위임
 */
public class ExternalJwtTokenService implements TokenService {

    private final SecretKey secretKey;
    private final RefreshTokenStore       refreshTokenStore;
    private final AuthenticationConverter authenticationConverter;

    public ExternalJwtTokenService(
            RefreshTokenStore       refreshTokenStore,
            AuthenticationConverter authenticationConverter,
            SecretKey secretKey) {
        this.refreshTokenStore       = refreshTokenStore;
        this.authenticationConverter = authenticationConverter;
        this.secretKey = secretKey;
    }

    @Override
    public String createAccessToken(Consumer<TokenBuilder> consumer) {

        AccessTokenBuilder accessTokenBuilder = new AccessTokenBuilder();
        consumer.accept(accessTokenBuilder);

        Instant now = Instant.now();
        return Jwts.builder()
                .setSubject(accessTokenBuilder.username)
                .claim("roles", accessTokenBuilder.roles)
                .addClaims(accessTokenBuilder.claims)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plusMillis(accessTokenBuilder.validity)))
                .signWith(secretKey)
                .compact();
    }

    @Override
    public String createRefreshToken(Consumer<TokenBuilder> consumer) {
        RefreshTokenBuilder refreshTokenBuilder = new RefreshTokenBuilder();
        consumer.accept(refreshTokenBuilder);

        Instant now = Instant.now();
        String token = Jwts.builder()
                .setSubject(refreshTokenBuilder.username)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plusMillis(refreshTokenBuilder.validity)))
                .signWith(secretKey)
                .compact();

        refreshTokenStore.store(token, refreshTokenBuilder.username);
        return token;
    }

    @Override
    public boolean validateAccessToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    @Override
    public Authentication getAuthenticationFromAccessToken(String token) {
        return authenticationConverter.getAuthentication(token);
    }

    @Override
    public String refreshAccessToken(String refreshToken) {
        // 1) 스토어에서 username 조회 → 없으면 유효하지 않은 토큰
        String username = refreshTokenStore.getUsername(refreshToken);
        if (username == null) {
            throw new JwtException("Invalid or expired refresh token");
        }
        List<String> roles = authenticationConverter.getRoles(refreshToken);

        // 3) 새 액세스 토큰 발급 (유효기간은 application 설정값)
        return createAccessToken(builder -> builder
                .username(username)
                .roles(roles)
                .validity(JwtStateStrategy.accessTokenValidity)
        );
    }

    @Override
    public void invalidateToken(String refreshToken) {
        refreshTokenStore.remove(refreshToken);
    }

    // ---------------------------------------
    // Builder 구현체
    // ---------------------------------------
    private static class AccessTokenBuilder implements TokenBuilder {
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
    }

    private static class RefreshTokenBuilder implements TokenBuilder {
        private String username;
        private long   validity;

        @Override
        public RefreshTokenBuilder username(String username) {
            this.username = username;
            return this;
        }

        @Override
        public RefreshTokenBuilder validity(long millis) {
            this.validity = millis;
            return this;
        }
    }
}

