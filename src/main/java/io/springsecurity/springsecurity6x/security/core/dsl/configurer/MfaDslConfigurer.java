package io.springsecurity.springsecurity6x.security.core.dsl.configurer;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.factor.ott.OttFactorDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.factor.passkey.PasskeyFactorDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.mfa.configurer.AdaptiveDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.mfa.configurer.RecoveryDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.mfa.configurer.RetryPolicyDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.MfaContinuationHandler;
import io.springsecurity.springsecurity6x.security.core.mfa.handler.MfaFailureHandler;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

public interface MfaDslConfigurer {
    MfaDslConfigurer order(int order);
    MfaDslConfigurer policyProvider(MfaPolicyProvider policyProvider);
    MfaDslConfigurer mfaContinuationHandler(MfaContinuationHandler continuationHandler);
    MfaDslConfigurer mfaFailureHandler(MfaFailureHandler failureHandler);
    MfaDslConfigurer finalSuccessHandler(AuthenticationSuccessHandler handler);
    MfaDslConfigurer defaultRetryPolicy(Customizer<RetryPolicyDslConfigurer> c);
    MfaDslConfigurer defaultAdaptivePolicy(Customizer<AdaptiveDslConfigurer> c);
    MfaDslConfigurer defaultDeviceTrustEnabled(boolean enable);

    // DSL 예시에 맞춘 메소드 추가 (primaryAuthentication 대신 또는 함께 사용)
    MfaDslConfigurer rest(Customizer<RestDslConfigurer> restConfigurer); // 여기서 RestDslConfigurer는 OptionsBuilderDsl을 확장해야 함
    MfaDslConfigurer ott(Customizer<OttFactorDslConfigurer> ottConfigurer);
    MfaDslConfigurer passkey(Customizer<PasskeyFactorDslConfigurer> passkeyConfigurer);
    MfaDslConfigurer recoveryFlow(Customizer<RecoveryDslConfigurer> recoveryConfigurer); // RecoveryDslConfigurer 정의 필요

    AuthenticationFlowConfig build();
}