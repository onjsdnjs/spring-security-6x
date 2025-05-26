package io.springsecurity.springsecurity6x.security.core.bootstrap;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.repository.UserRepository;
import io.springsecurity.springsecurity6x.security.core.asep.annotation.EnableAsep;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.DefaultMfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import io.springsecurity.springsecurity6x.security.filter.handler.MfaStateMachineIntegrator;
import io.springsecurity.springsecurity6x.security.handler.MfaFactorProcessingSuccessHandler;
import io.springsecurity.springsecurity6x.security.handler.UnifiedAuthenticationFailureHandler;
import io.springsecurity.springsecurity6x.security.handler.UnifiedAuthenticationSuccessHandler;
import io.springsecurity.springsecurity6x.security.handler.logout.JwtLogoutHandler;
import io.springsecurity.springsecurity6x.security.utils.writer.AuthResponseWriter;
import io.springsecurity.springsecurity6x.security.utils.writer.JsonAuthResponseWriter;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.authentication.logout.LogoutHandler;


@Configuration
@RequiredArgsConstructor
@EnableAsep
public class MfaInfrastructureAutoConfiguration {

    private final AuthContextProperties authContextProperties;
    private final TokenService tokenService;
    private final UserRepository userRepository;

    @Bean
    @ConditionalOnMissingBean
    public MfaPolicyProvider mfaPolicyProvider(ApplicationContext applicationContext,MfaStateMachineIntegrator mfaStateMachineIntegrator) {
        return new DefaultMfaPolicyProvider(userRepository, applicationContext, mfaStateMachineIntegrator);
    }

    @Bean
    @ConditionalOnMissingBean
    public UnifiedAuthenticationSuccessHandler unifiedAuthenticationSuccessHandler(AuthResponseWriter authResponseWriter,
                                                                                    MfaPolicyProvider mfaPolicyProvider,
                                                                                   ApplicationContext applicationContext,
                                                                                   MfaStateMachineIntegrator MfaStateMachineIntegrator) {
        return new UnifiedAuthenticationSuccessHandler(mfaPolicyProvider, tokenService,authResponseWriter,
                                                        authContextProperties, applicationContext, MfaStateMachineIntegrator);
    }

    @Bean
    @ConditionalOnMissingBean
    public UnifiedAuthenticationFailureHandler unifiedAuthenticationFailureHandler(MfaStateMachineIntegrator mfaStateMachineIntegrator,
                                                                                   MfaPolicyProvider mfaPolicyProvider,
                                                                          AuthResponseWriter authResponseWriter,
                                                                          AuthContextProperties properties) {
        return new UnifiedAuthenticationFailureHandler(mfaStateMachineIntegrator, mfaPolicyProvider, authResponseWriter, properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public MfaFactorProcessingSuccessHandler mfaFactorProcessingSuccessHandler(MfaStateMachineIntegrator mfaStateMachineIntegrator,
                                                                               MfaPolicyProvider mfaPolicyProvider,
                                                                               AuthResponseWriter authResponseWriter,
                                                                               AuthContextProperties properties,
                                                                               ApplicationContext applicationContext,
                                                                               UnifiedAuthenticationSuccessHandler successHandler) {
        return new MfaFactorProcessingSuccessHandler(mfaStateMachineIntegrator, mfaPolicyProvider,successHandler,
                                                    authResponseWriter, applicationContext, properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public LogoutHandler jwtLogoutHandler(TokenService tokenService, AuthResponseWriter authResponseWriter) {
        return new JwtLogoutHandler(tokenService, authResponseWriter);
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthResponseWriter authResponseWriter(ObjectMapper objectMapper) {
        return new JsonAuthResponseWriter(objectMapper);
    }
}
