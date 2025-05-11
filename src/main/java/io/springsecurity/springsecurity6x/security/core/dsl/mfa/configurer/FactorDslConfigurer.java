package io.springsecurity.springsecurity6x.security.core.dsl.mfa.configurer;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;

/**
 * 개별 인증 스텝 설정용 DSL 인터페이스
 */
public interface FactorDslConfigurer {
    FactorDslConfigurer type(String factorType);
    // 각 factor별 커스터마이징 메서드 추가 가능
    AuthenticationStepConfig toConfig();
}
