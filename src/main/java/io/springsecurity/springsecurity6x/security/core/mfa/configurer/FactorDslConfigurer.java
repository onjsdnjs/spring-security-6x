package io.springsecurity.springsecurity6x.security.core.mfa.configurer;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;

/**
 * 개별 인증 스텝 설정용 DSL 인터페이스
 */
public interface FactorDslConfigurer {
    FactorDslConfigurer type(String factorType);
    AuthenticationStepConfig toConfig();
}
