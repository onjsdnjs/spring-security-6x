package io.springsecurity.springsecurity6x.security.core.bootstrap;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.repository.UserRepository;
import io.springsecurity.springsecurity6x.security.core.mfa.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.HttpSessionContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.DefaultMfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.handler.MfaAuthenticationFailureHandler;
import io.springsecurity.springsecurity6x.security.handler.MfaCapableRestSuccessHandler;
import io.springsecurity.springsecurity6x.security.handler.MfaStepBasedSuccessHandler;
import io.springsecurity.springsecurity6x.security.handler.logout.JwtLogoutHandler;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.web.authentication.logout.LogoutHandler;

@AutoConfiguration
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

    // 플랫폼 기본 제공 핸들러 Bean 등록
    @Bean
    @ConditionalOnMissingBean
    public MfaCapableRestSuccessHandler mfaCapableRestSuccessHandler(ContextPersistence contextPersistence,
                                                                     MfaPolicyProvider mfaPolicyProvider) {
        return new MfaCapableRestSuccessHandler(contextPersistence, mfaPolicyProvider, tokenService, authContextProperties);
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
                authContextProperties.getMfa().getFailureUrl() : "/mfa/failure"; // application.yml 에서 mfa.failure-url 설정 가능
        return new MfaAuthenticationFailureHandler(failureUrl, contextPersistence, mfaPolicyProvider);
    }

    @Bean
    @ConditionalOnMissingBean(name = "jwtLogoutHandler") // 이름으로 구분
    public LogoutHandler jwtLogoutHandler(TokenService tokenService) {
        return new JwtLogoutHandler(tokenService);
    }
}
