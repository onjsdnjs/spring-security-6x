package io.springsecurity.springsecurity6x.security.configuration;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.springsecurity.springsecurity6x.security.tokenstore.InMemoryRefreshTokenStore;
import io.springsecurity.springsecurity6x.security.tokenstore.RefreshTokenStore;
import io.springsecurity.springsecurity6x.security.converter.JwtAuthenticationConverter;
import io.springsecurity.springsecurity6x.security.converter.SpringAuthenticationConverter;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.tokenservice.ExternalJwtTokenService;
import io.springsecurity.springsecurity6x.security.tokenservice.OAuth2JwtTokenService;
import io.springsecurity.springsecurity6x.security.tokenservice.TokenService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;

import javax.crypto.SecretKey;

@Configuration
@EnableConfigurationProperties(AuthContextProperties.class)
public class JwtSecurityAutoConfiguration {

    SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    @Bean
    @ConditionalOnProperty(name = "spring.auth.token-control-mode", havingValue = "internal")
    public TokenService internalTokenService(JwtEncoder encoder, JwtDecoder decoder) {
        return new OAuth2JwtTokenService(encoder, decoder, refreshTokenStore(), new SpringAuthenticationConverter(decoder));
    }


    @Bean
    @ConditionalOnProperty(name = "spring.auth.token-control-mode", havingValue = "external")
    public TokenService externalTokenService() {
        return new ExternalJwtTokenService(
                refreshTokenStore(),
                new JwtAuthenticationConverter(key),
                key
        );
    }

    @Bean
    public RefreshTokenStore refreshTokenStore() {
        return new InMemoryRefreshTokenStore(key); // 나중에 Redis로 교체 가능
    }
}
