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

public class JwtsTokenService extends JwtTokenService {

    private final SecretKey secretKey;

    public JwtsTokenService(RefreshTokenStore store, AuthenticationConverter converter, SecretKey secretKey) {
        super(store, converter);
        this.secretKey = secretKey;
    }

    @Override
    public String createAccessToken(Consumer<TokenBuilder> consumer) {
        DefaultTokenBuilder builder = new DefaultTokenBuilder();
        consumer.accept(builder);

        Instant now = Instant.now();
        String jti = UUID.randomUUID().toString();

        return Jwts.builder()
                .setId(jti)
                .setSubject(builder.getUsername())
                .claim("roles", builder.getRoles())
                .claim("token_type", "access")
                .addClaims(builder.getClaims())
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plusMillis(
                        builder.getValidity()
                )))
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
                .claim("token_type", "refresh")
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plusMillis(JwtStateStrategy.REFRESH_TOKEN_VALIDITY)))
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

}

