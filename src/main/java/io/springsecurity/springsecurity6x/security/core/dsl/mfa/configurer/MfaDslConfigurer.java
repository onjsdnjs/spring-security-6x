package io.springsecurity.springsecurity6x.security.core.dsl.mfa.configurer;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;

/**
 * MFA 전용 DSL: factor 순서, retryPolicy, adaptive 옵션 등 추가
 */
public interface MfaDslConfigurer {
    MfaDslConfigurer factor(java.util.function.Consumer<FactorDslConfigurer> c);
    MfaDslConfigurer order(int order);
    MfaDslConfigurer retryPolicy(java.util.function.Consumer<RetryPolicyDslConfigurer> c);
    MfaDslConfigurer adaptive(java.util.function.Consumer<AdaptiveDslConfigurer> c);
    MfaDslConfigurer deviceTrust(boolean enable);
    MfaDslConfigurer recoveryFlow(java.util.function.Consumer<RecoveryDslConfigurer> c);
    AuthenticationFlowConfig build();
}