package io.springsecurity.springsecurity6x.security.core.bootstrap;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.creator.JwtTokenCreator;
import io.springsecurity.springsecurity6x.security.token.creator.TokenCreator;
import io.springsecurity.springsecurity6x.security.token.parser.JwtTokenParser;
import io.springsecurity.springsecurity6x.security.token.parser.TokenParser;
import io.springsecurity.springsecurity6x.security.token.service.JwtTokenService;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import io.springsecurity.springsecurity6x.security.token.store.RefreshTokenStore;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportStrategy;
import io.springsecurity.springsecurity6x.security.token.transport.TokenTransportStrategyFactory;
import io.springsecurity.springsecurity6x.security.token.validator.JwtTokenValidator;
import io.springsecurity.springsecurity6x.security.token.validator.TokenValidator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import javax.crypto.SecretKey;

/**
 * 토큰 서비스 관련 설정
 *
 * JWT 기반 토큰 서비스를 구성합니다.
 * RefreshTokenStore는 TokenStoreConfiguration 에서 생성되므로
 * 이 설정은 토큰 서비스 관련 빈들만 생성합니다.
 *
 * @since 2024.12 - RefreshTokenStore 분리
 */
@Slf4j
@Configuration
@Import(io.springsecurity.springsecurity6x.security.token.store.TokenStoreConfiguration.class)
public class TokenServiceConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public SecretKey jwtSecretKey(AuthContextProperties props) {
        // 실제 운영에서는 application.yml 등에서 시크릿 키를 주입받거나 안전하게 관리해야 함
        // 여기서는 임시로 생성하거나, props 에서 가져오는 로직 추가 가능
        // if (StringUtils.hasText(props.getJwtSecret())) {
        //     return Keys.hmacShaKeyFor(props.getJwtSecret().getBytes(StandardCharsets.UTF_8));
        // }
        log.warn("Using auto-generated JWT secret key. This should not be used in production!");
        return Keys.secretKeyFor(SignatureAlgorithm.HS256); // 개발용 임시 키
    }

    @Bean
    @ConditionalOnMissingBean(TokenParser.class)
    public JwtTokenParser jwtTokenParser(SecretKey secretKey) {
        return new JwtTokenParser(secretKey);
    }

    @Bean
    @ConditionalOnMissingBean(TokenCreator.class)
    public JwtTokenCreator jwtTokenCreator(SecretKey secretKey) {
        return new JwtTokenCreator(secretKey);
    }

    @Bean
    @ConditionalOnMissingBean(TokenValidator.class)
    public JwtTokenValidator jwtTokenValidator(TokenParser tokenParser,
                                               RefreshTokenStore refreshTokenStore,
                                               AuthContextProperties props) {
        return new JwtTokenValidator(tokenParser, refreshTokenStore,
                props.getRefreshRotateThreshold());
    }

    @Bean
    @ConditionalOnMissingBean(TokenService.class)
    public TokenService tokenService(TokenValidator tokenValidator,
                                     TokenCreator tokenCreator,
                                     RefreshTokenStore refreshTokenStore,
                                     AuthContextProperties props,
                                     ObjectMapper objectMapper) {

        TokenTransportStrategy transport = TokenTransportStrategyFactory.create(props);

        log.info("Creating JwtTokenService with {} refresh token store",
                props.getTokenStoreType());

        return new JwtTokenService(
                tokenValidator,
                tokenCreator,
                refreshTokenStore,
                transport,
                props,
                objectMapper
        );
    }
}