package io.springsecurity.springsecurity6x.jwt.configuration;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.springsecurity.springsecurity6x.jwt.InMemoryRefreshTokenStore;
import io.springsecurity.springsecurity6x.jwt.annotation.RefreshTokenStore;
import io.springsecurity.springsecurity6x.jwt.converter.JwtAuthenticationConverter;
import io.springsecurity.springsecurity6x.jwt.converter.SpringAuthenticationConverter;
import io.springsecurity.springsecurity6x.jwt.tokenservice.ExternalJwtTokenService;
import io.springsecurity.springsecurity6x.jwt.tokenservice.InternalJwtTokenService;
import io.springsecurity.springsecurity6x.jwt.tokenservice.TokenService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;

import java.security.Key;

@Configuration
public class JwtSecurityAutoConfiguration {

    @Bean
    @ConditionalOnProperty(name = "spring.auth.token.type", havingValue = "INTERNAL")
    public TokenService internalTokenService(JwtEncoder encoder, JwtDecoder decoder) {
        return new InternalJwtTokenService(encoder, decoder, refreshTokenStore(), new SpringAuthenticationConverter(decoder));
    }


    @Bean
    @ConditionalOnProperty(name = "spring.auth.token.type", havingValue = "EXTERNAL")
    public TokenService externalTokenService() {
        Key secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        return new ExternalJwtTokenService(refreshTokenStore(), new JwtAuthenticationConverter(secretKey), secretKey);
    }

    @Bean
    public RefreshTokenStore refreshTokenStore() {
        return new InMemoryRefreshTokenStore(); // 나중에 Redis로 교체 가능
    }
}
