/*
package io.springsecurity.springsecurity6x.security.configuration;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.springsecurity.springsecurity6x.security.token.parser.ExternalJwtParser;
import io.springsecurity.springsecurity6x.security.token.parser.InternalJwtParser;
import io.springsecurity.springsecurity6x.security.token.parser.JwtParser;
import io.springsecurity.springsecurity6x.security.token.store.*;
import io.springsecurity.springsecurity6x.security.converter.JwtAuthenticationConverter;
import io.springsecurity.springsecurity6x.security.converter.SpringAuthenticationConverter;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;

import javax.crypto.SecretKey;

@Configuration
@EnableConfigurationProperties(AuthContextProperties.class)
public class JwtSecurityAutoConfiguration {

    @Bean
    public SecretKey secretKey(JwtEncoder jwtEncoder, JwtDecoder jwtDecoder) {
        return Keys.secretKeyFor(SignatureAlgorithm.HS256);
    }


    @Bean
    @ConditionalOnProperty(name = "spring.auth.token-issuer", havingValue = "internal")
    public TokenService internalTokenService(ApplicationContext applicationContext) {
        InternalJwtParser parser = new InternalJwtParser(key);
        return new JwtsTokenProvider(
                refreshTokenStore(parser),
                new JwtAuthenticationConverter(parser),
                key, applicationContext
        );
    }

    private RefreshTokenStore refreshTokenStore(JwtParser parser) {
        return new InMemoryRefreshTokenStore(parser); // 나중에 Redis로 교체 가능
    }
}
*/
