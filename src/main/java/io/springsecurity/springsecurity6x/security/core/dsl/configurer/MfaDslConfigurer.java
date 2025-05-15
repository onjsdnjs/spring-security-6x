package io.springsecurity.springsecurity6x.security.core.dsl.configurer;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.configurer.AdaptiveDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.mfa.configurer.RetryPolicyDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.MfaContinuationHandler;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.MfaFailureHandler;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

public interface MfaDslConfigurer {

    MfaDslConfigurer order(int order);
    MfaDslConfigurer form(Customizer<FormDslConfigurer> formConfigurer);
    MfaDslConfigurer rest(Customizer<RestDslConfigurer> restConfigurer);
    MfaDslConfigurer ott(Customizer<OttDslConfigurer> ottConfigurer);
    MfaDslConfigurer passkey(Customizer<PasskeyDslConfigurer> passkeyConfigurer);
    MfaDslConfigurer recoveryFlow(Customizer<RecoveryCodeDslConfigurer> recoveryConfigurerCustomizer);
    MfaDslConfigurer mfaContinuationHandler(MfaContinuationHandler continuationHandler);
    MfaDslConfigurer mfaFailureHandler(MfaFailureHandler failureHandler);
    MfaDslConfigurer finalSuccessHandler(AuthenticationSuccessHandler handler);
    MfaDslConfigurer policyProvider(MfaPolicyProvider policyProvider);
    MfaDslConfigurer defaultRetryPolicy(Customizer<RetryPolicyDslConfigurer> c);
    MfaDslConfigurer defaultAdaptivePolicy(Customizer<AdaptiveDslConfigurer> c);
    MfaDslConfigurer defaultDeviceTrustEnabled(boolean enable);
    AuthenticationFlowConfig build();

    // 이 메소드는 PlatformSecurityConfig.java의 DSL 에서는 직접 사용되지 않으나,
    // 내부적으로 다른 방식으로 1차 인증을 설정할 경우를 위해 남겨둘 수 있습니다.
    // 현재 DSL 흐름에서는 rest()가 그 역할을 대신하고 있습니다.
    MfaDslConfigurer primaryAuthentication(Customizer<PrimaryAuthDslConfigurer> primaryAuthConfig);
}