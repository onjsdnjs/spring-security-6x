package io.springsecurity.springsecurity6x.security.tokenservice;

import io.jsonwebtoken.Jwts;
import io.springsecurity.springsecurity6x.security.configurer.state.JwtStateStrategy;
import io.springsecurity.springsecurity6x.security.converter.AuthenticationConverter;
import io.springsecurity.springsecurity6x.security.tokenstore.RefreshTokenStore;
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
public class ExternalJwtTokenService extends JwtTokenService {

    private final SecretKey secretKey;

    public ExternalJwtTokenService(
            RefreshTokenStore refreshTokenStore,
            AuthenticationConverter authenticationConverter,
            SecretKey secretKey) {
        super(refreshTokenStore, authenticationConverter);
        this.secretKey = secretKey;
    }

    @Override
    public String createAccessToken(Consumer<TokenBuilder> consumer) {
        DefaultTokenBuilder builder = new DefaultTokenBuilder();
        consumer.accept(builder);

        Instant now = Instant.now();
        String jti = UUID.randomUUID().toString();

        return Jwts.builder()
                .setId(jti)                                  // JTI: 토큰 고유 ID
                .setSubject(builder.getUsername())            // sub: 사용자 식별자
                .claim("roles", builder.getRoles())           // roles: 권한 정보
                .claim("token_type", "access")                // token_type: 액세스 토큰 구분자
                .addClaims(builder.getClaims())               // custom claims
                .setIssuedAt(Date.from(now))                  // iat
                .setExpiration(Date.from(now.plusMillis(
                        builder.getValidity()                  // 유효기간: builder에 지정된 값
                )))
                .signWith(secretKey)
                .compact();
    }

    @Override
    public String createRefreshToken(Consumer<TokenBuilder> consumer) {
        DefaultTokenBuilder tokenBuilder = new DefaultTokenBuilder();
        consumer.accept(tokenBuilder);

        Instant now = Instant.now();
        String jti = UUID.randomUUID().toString();  // 토큰 고유 ID

        String token = Jwts.builder()
                // Header
                .setId(jti)                                        // JTI
                .setSubject(tokenBuilder.getUsername())                 // 사용자 식별자
                .claim("token_type", "refresh")                    // 토큰 타입
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plusMillis(
                        JwtStateStrategy.refreshTokenValidity)))
                // 서명
                .signWith(secretKey)                        // 액세스 토큰과 다른 키를 쓰면 더 안전
                .compact();

        refreshTokenStore.store(token, tokenBuilder.getUsername());

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

}

