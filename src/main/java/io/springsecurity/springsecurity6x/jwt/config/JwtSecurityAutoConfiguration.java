package io.springsecurity.springsecurity6x.jwt.config;

import io.springsecurity.springsecurity6x.jwt.InMemoryRefreshTokenStore;
import io.springsecurity.springsecurity6x.jwt.JwtProperties;
import io.springsecurity.springsecurity6x.jwt.annotation.RefreshTokenStore;
import io.springsecurity.springsecurity6x.jwt.tokenservice.JwtTokenService;
import io.springsecurity.springsecurity6x.jwt.tokenservice.SpringJwtTokenService;
import io.springsecurity.springsecurity6x.jwt.tokenservice.TokenService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;

@Configuration
@EnableConfigurationProperties(JwtProperties.class)
public class JwtSecurityAutoConfiguration {

    @Bean
    @ConditionalOnProperty(name = "jwt.provider", havingValue = "spring", matchIfMissing = true)
    public TokenService springTokenService(JwtEncoder encoder, JwtDecoder decoder, RefreshTokenStore refreshTokenStore) {
        return new SpringJwtTokenService(encoder, decoder, refreshTokenStore);
    }


    @Bean
    @ConditionalOnProperty(name = "jwt.provider", havingValue = "jwt", matchIfMissing = true)
    public TokenService jwtTokenService() {
        return new JwtTokenService();
    }

    @Bean
    @ConditionalOnMissingBean
    public RefreshTokenStore refreshTokenStore() {
        return new InMemoryRefreshTokenStore(); // 나중에 Redis로 교체 가능
    }
}
