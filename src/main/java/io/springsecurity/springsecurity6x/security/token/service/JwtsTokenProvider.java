package io.springsecurity.springsecurity6x.security.token.service;

import io.jsonwebtoken.*;
import io.springsecurity.springsecurity6x.security.configurer.state.JwtStateStrategy;
import io.springsecurity.springsecurity6x.security.converter.AuthenticationConverter;
import io.springsecurity.springsecurity6x.security.token.parser.ParsedJwt;
import io.springsecurity.springsecurity6x.security.token.store.RefreshTokenStore;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;

public class JwtsTokenProvider extends JwtTokenService {

    private final SecretKey secretKey;
    private final long rotationThresholdMillis = Duration.ofHours(12).toMillis();

    public JwtsTokenProvider(RefreshTokenStore store, AuthenticationConverter converter, SecretKey secretKey) {
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
    public boolean validateAccessToken(String accessToken) {
        if (!StringUtils.hasText(accessToken)) {
            return false;
        }
            Jwts.parserBuilder()
                    .setSigningKey(secretKey)   // 액세스 전용 키
                    .build()
                    .parseClaimsJws(accessToken);

        return true;
    }

    @Override
    public boolean validateRefreshToken(String refreshToken) {
        if (!StringUtils.hasText(refreshToken)) {
            return false;
        }
        Jws<Claims> jws = Jwts.parserBuilder()
                .setSigningKey(secretKey)   // 리프레시 전용 키
                .build()
                .parseClaimsJws(refreshToken);

        // 2) 서버 저장소에서 무효화 여부 확인
        String username = refreshTokenStore().getUsername(refreshToken);
        return username != null;
    }

    @Override
    public boolean shouldRotateRefreshToken(String refreshToken) {
        ParsedJwt jwt = refreshTokenStore().parser().parse(refreshToken);
        long remain = jwt.getExpiration().toEpochMilli() - System.currentTimeMillis();
        return remain <= rotationThresholdMillis;
    }

    @Override
    public String createAccessTokenFromRefresh(String refreshToken) {
        // 서명 검증+클레임 파싱
        ParsedJwt jwt = refreshTokenStore().parser().parse(refreshToken);
        String username = jwt.getSubject();
        List<String> roles = authenticationConverter().getRoles(refreshToken);

        // 엑세스 토큰만 새로 발급
        return createAccessToken(builder -> builder
                .username(username)
                .roles(roles)
                .validity(JwtStateStrategy.ACCESS_TOKEN_VALIDITY)
        );
    }
}

