package io.springsecurity.springsecurity6x.security.core.bootstrap;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.repository.UserRepository;
import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.HttpSessionContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.DefaultMfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.handler.JwtEmittingAndMfaAwareSuccessHandler;
import io.springsecurity.springsecurity6x.security.handler.MfaAuthenticationFailureHandler;
import io.springsecurity.springsecurity6x.security.handler.MfaCapableRestSuccessHandler;
import io.springsecurity.springsecurity6x.security.handler.MfaStepBasedSuccessHandler;
import io.springsecurity.springsecurity6x.security.handler.logout.JwtLogoutHandler;
import io.springsecurity.springsecurity6x.security.http.AuthResponseWriter;
import io.springsecurity.springsecurity6x.security.http.JsonAuthResponseWriter;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.authentication.logout.LogoutHandler;

@Configuration
@EnableConfigurationProperties(AuthContextProperties.class)
@RequiredArgsConstructor
public class MfaInfrastructureAutoConfiguration {

    private final AuthContextProperties authContextProperties;
    private final ObjectMapper objectMapper;
    private final TokenService tokenService;
    private final UserRepository userRepository;

    @Bean
    @ConditionalOnMissingBean
    public ContextPersistence contextPersistence() {
        return new HttpSessionContextPersistence();
    }

    @Bean
    @ConditionalOnMissingBean
    public MfaPolicyProvider mfaPolicyProvider() {
        return new DefaultMfaPolicyProvider(userRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public MfaCapableRestSuccessHandler mfaCapableRestSuccessHandler(ContextPersistence contextPersistence,
                                                                     MfaPolicyProvider mfaPolicyProvider, AuthResponseWriter authResponseWriter) {
        return new MfaCapableRestSuccessHandler(contextPersistence, mfaPolicyProvider, tokenService, authContextProperties, authResponseWriter);
    }

    @Bean
    @ConditionalOnMissingBean
    public MfaStepBasedSuccessHandler mfaStepBasedSuccessHandler(MfaPolicyProvider mfaPolicyProvider,
                                                                 ContextPersistence contextPersistence) {
        return new MfaStepBasedSuccessHandler(tokenService, mfaPolicyProvider, contextPersistence);
    }

    @Bean
    @ConditionalOnMissingBean
    public MfaAuthenticationFailureHandler mfaAuthenticationFailureHandler(ContextPersistence contextPersistence,
                                                                           MfaPolicyProvider mfaPolicyProvider) {
        String failureUrl = authContextProperties.getMfa() != null && authContextProperties.getMfa().getFailureUrl() != null ?
                authContextProperties.getMfa().getFailureUrl() : "/mfa/failure";
        return new MfaAuthenticationFailureHandler(failureUrl, contextPersistence, mfaPolicyProvider);
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtEmittingAndMfaAwareSuccessHandler jwtEmittingAndMfaAwareSuccessHandler(
            TokenService tokenService,
            ObjectMapper objectMapper,
            UserRepository userRepository,
            ContextPersistence contextPersistence,
            AuthContextProperties authContextProperties) {

        return new JwtEmittingAndMfaAwareSuccessHandler(
                tokenService,
                objectMapper,
                "/", // 기본 성공 URL
                userRepository,
                contextPersistence,
                authContextProperties
        );
    }

    @Bean
    @ConditionalOnMissingBean
    public LogoutHandler jwtLogoutHandler(TokenService tokenService) {
        return new JwtLogoutHandler(tokenService);
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthResponseWriter authResponseWriter(ObjectMapper objectMapper) {
        return new JsonAuthResponseWriter(objectMapper);
    }
}
