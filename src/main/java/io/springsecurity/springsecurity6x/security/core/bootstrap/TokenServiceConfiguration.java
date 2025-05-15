package io.springsecurity.springsecurity6x.security.core.bootstrap;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.creator.JwtTokenCreator;
import io.springsecurity.springsecurity6x.security.token.parser.JwtTokenParser;
import io.springsecurity.springsecurity6x.security.token.service.JwtTokenService;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import io.springsecurity.springsecurity6x.security.token.store.JwtRefreshTokenStore;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportStrategy;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportStrategyFactory;
import io.springsecurity.springsecurity6x.security.token.validator.JwtTokenValidator;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;

@Configuration
public class TokenServiceConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public SecretKey jwtSecretKey(AuthContextProperties props) {
        // 실제 운영에서는 application.yml 등에서 시크릿 키를 주입받거나 안전하게 관리해야 함
        // 여기서는 임시로 생성하거나, props 에서 가져오는 로직 추가 가능
        // if (StringUtils.hasText(props.getJwtSecret())) {
        //     return Keys.hmacShaKeyFor(props.getJwtSecret().getBytes(StandardCharsets.UTF_8));
        // }
        return Keys.secretKeyFor(SignatureAlgorithm.HS256); // 개발용 임시 키
    }

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
                                     ObjectMapper objectMapper,
                                     SecretKey secretKey) {

        TokenTransportStrategy transport = TokenTransportStrategyFactory.create(props);

        JwtTokenService jwtTokenService = new JwtTokenService(
                jwtTokenValidator,
                jwtTokenCreator,
                jwtRefreshTokenStore,
                transport,
                props,
                objectMapper);

        transport.setTokenService(jwtTokenService);

        return jwtTokenService;
    }
}