package io.springsecurity.springsecurity6x.security.tokenservice;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.springsecurity.springsecurity6x.security.configurer.state.JwtStateStrategy;
import io.springsecurity.springsecurity6x.security.converter.AuthenticationConverter;
import io.springsecurity.springsecurity6x.security.converter.JwtAuthenticationConverter;
import io.springsecurity.springsecurity6x.security.tokenstore.RefreshTokenStore;
import org.springframework.security.oauth2.jwt.JwtException;

import javax.crypto.SecretKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;

public class JwtsTokenService extends JwtTokenService {

    private final SecretKey secretKey;
    private final long rotationThresholdMillis = Duration.ofDays(1).toMillis();

    public JwtsTokenService(RefreshTokenStore store, AuthenticationConverter converter, SecretKey secretKey) {
        super(store, converter);
        this.secretKey = secretKey;
    }

    @Override
    public String createAccessToken(Consumer<TokenBuilder> consumer) {

        DefaultTokenBuilder tokenBuilder = new DefaultTokenBuilder();
        consumer.accept(tokenBuilder);

        Instant now = Instant.now();
        String jti = UUID.randomUUID().toString();

        return Jwts.builder()
                .setId(jti)
                .setSubject(tokenBuilder.getUsername())
                .claim("roles", tokenBuilder.getRoles())
                .claim("token_type", "access")
                .addClaims(tokenBuilder.getClaims())
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plusMillis(tokenBuilder.getValidity())))
                .signWith(secretKey)
                .compact();
    }

    @Override
    public String createRefreshToken(Consumer<TokenBuilder> consumer) {

        DefaultTokenBuilder tokenBuilder = new DefaultTokenBuilder();
        consumer.accept(tokenBuilder);

        Instant now = Instant.now();
        String jti = UUID.randomUUID().toString();

        String token = Jwts.builder()
                .setId(jti)
                .setSubject(tokenBuilder.getUsername())
                .claim("roles", tokenBuilder.getRoles())
                .claim("token_type", "refresh")
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plusMillis(tokenBuilder.getValidity())))
                .signWith(secretKey)
                .compact();

        refreshTokenStore().store(token, tokenBuilder.getUsername());

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
    public boolean shouldRotateRefreshToken(String refreshToken) {
        Claims claims = ((JwtAuthenticationConverter)authenticationConverter()).parseClaims(refreshToken);
        long remain = claims.getExpiration().getTime() - System.currentTimeMillis();
        return remain <= rotationThresholdMillis;
    }

    @Override
    public String createAccessTokenFromRefresh(String refreshToken) {
        // 서명 검증+클레임 파싱
        Claims claims = ((JwtAuthenticationConverter)authenticationConverter()).parseClaims(refreshToken);
        String username = claims.getSubject();
        List<String> roles = authenticationConverter().getRoles(refreshToken);

        // 엑세스 토큰만 새로 발급
        return createAccessToken(builder -> builder
                .username(username)
                .roles(roles)
                .validity(JwtStateStrategy.ACCESS_TOKEN_VALIDITY)
        );
    }

}

