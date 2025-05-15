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

        // ObjectMapper 전달
        // TokenTransportStrategy 가 TokenService 를 필요로 하는 경우 (순환 참조 방지)
        // transport.setTokenService(jwtTokenService); // JwtTokenService 생성자에서 transport에 자신을 주입하도록 변경 가능
        // 또는 TokenService에 objectMapper를 주입하여 JSON 처리를 위임하고,
        // TokenTransportStrategy는 순수하게 토큰 전달 방식만 담당하도록 분리.
        // 현재 JwtTokenService 생성자에 ObjectMapper 추가함.
        return new JwtTokenService(
                jwtTokenValidator,
                jwtTokenCreator,
                jwtRefreshTokenStore,
                transport,
                props,
                objectMapper
        );
    }

    // SecretKey, AuthContextProperties, ObjectMapper 는 다른 Configuration에서 Bean으로 등록되어 있다고 가정
    // 예: MySecurityConfig.java, SecurityPlatformConfiguration.java
}