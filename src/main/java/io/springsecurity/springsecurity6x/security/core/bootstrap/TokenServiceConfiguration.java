package io.springsecurity.springsecurity6x.security.core.bootstrap;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.creator.JwtTokenCreator;
import io.springsecurity.springsecurity6x.security.token.parser.JwtTokenParser;
import io.springsecurity.springsecurity6x.security.token.service.JwtTokenService;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import io.springsecurity.springsecurity6x.security.token.store.JwtRefreshTokenStore;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportStrategy;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportStrategyFactory;
import io.springsecurity.springsecurity6x.security.token.validator.JwtTokenValidator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;

@Configuration
public class TokenServiceConfiguration {

    @Bean
    public JwtTokenParser jwtTokenParser(SecretKey secretKey) {
        return new JwtTokenParser(secretKey);
    }

    @Bean
    public JwtRefreshTokenStore jwtRefreshTokenStore(JwtTokenParser jwtTokenParser, AuthContextProperties props) {
        return new JwtRefreshTokenStore(jwtTokenParser, props);
    }

    @Bean
    public JwtTokenCreator jwtTokenCreator(SecretKey secretKey) {
        return new JwtTokenCreator(secretKey);
    }

    @Bean
    public JwtTokenValidator jwtTokenValidator(JwtTokenParser jwtTokenParser, JwtRefreshTokenStore jwtRefreshTokenStore, AuthContextProperties props) {
        return new JwtTokenValidator(jwtTokenParser, jwtRefreshTokenStore, props.getRefreshRotateThreshold());
    }

    @Bean
    public TokenService tokenService(JwtTokenValidator jwtTokenValidator,
                                     JwtTokenCreator jwtTokenCreator,
                                     JwtRefreshTokenStore jwtRefreshTokenStore,
                                     AuthContextProperties props,
                                     ObjectMapper objectMapper) { // ObjectMapper 주입 추가

        TokenTransportStrategy transport = TokenTransportStrategyFactory.create(props);

        return new JwtTokenService(
                jwtTokenValidator,
                jwtTokenCreator,
                jwtRefreshTokenStore,
                transport,
                props,
                objectMapper
        );
    }
}