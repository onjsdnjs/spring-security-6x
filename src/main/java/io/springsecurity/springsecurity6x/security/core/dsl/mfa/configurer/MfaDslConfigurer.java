package io.springsecurity.springsecurity6x.security.core.dsl.mfa.configurer;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;

/**
 * MFA 전용 DSL: factor 순서, retryPolicy, adaptive 옵션 등 추가
 */
public interface MfaDslConfigurer extends MultiStepDslConfigurer {
    MfaDslConfigurer factor(java.util.function.Consumer<FactorDslConfigurer> c);
    MfaDslConfigurer order(int order);
    AuthenticationFlowConfig build();
}
