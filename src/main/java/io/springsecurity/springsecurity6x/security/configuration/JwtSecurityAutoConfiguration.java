package io.springsecurity.springsecurity6x.security.configuration;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.springsecurity.springsecurity6x.security.tokenstore.*;
import io.springsecurity.springsecurity6x.security.converter.JwtAuthenticationConverter;
import io.springsecurity.springsecurity6x.security.converter.SpringAuthenticationConverter;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.tokenservice.JwtsTokenProvider;
import io.springsecurity.springsecurity6x.security.tokenservice.OAuth2TokenProvider;
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
    @ConditionalOnProperty(name = "spring.auth.token-control-mode", havingValue = "OAUTH2")
    public TokenService internalTokenService(JwtEncoder jwtEncoder, JwtDecoder jwtDecoder) {
        return new OAuth2TokenProvider(
                jwtEncoder,
                jwtDecoder,
                refreshTokenStore(new OAuth2RefreshTokenParser(key)),
                new SpringAuthenticationConverter(jwtDecoder));
    }


    @Bean
    @ConditionalOnProperty(name = "spring.auth.token-control-mode", havingValue = "JWTS")
    public TokenService externalTokenService() {
        return new JwtsTokenProvider(
                refreshTokenStore(new JwtsRefreshTokenParser(key)),
                new JwtAuthenticationConverter(key),
                key
        );
    }

    private RefreshTokenStore refreshTokenStore(RefreshTokenParser parser) {
        return new InMemoryRefreshTokenStore(parser); // 나중에 Redis로 교체 가능
    }
}
