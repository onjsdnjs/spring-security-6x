package io.springsecurity.springsecurity6x.security.core.mfa.configurer;

/**
 * 멀티 스텝 인증 플로우를 구성하기 위한 공통 인터페이스
 */
public interface MultiStepDslConfigurer {
    MultiStepDslConfigurer retryPolicy(java.util.function.Consumer<RetryPolicyDslConfigurer> c);
    MultiStepDslConfigurer adaptive(java.util.function.Consumer<AdaptiveDslConfigurer> c);
    MultiStepDslConfigurer deviceTrust(boolean enable);
    MultiStepDslConfigurer recoveryFlow(java.util.function.Consumer<RecoveryDslConfigurer> c);
}

