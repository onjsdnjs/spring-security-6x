package io.springsecurity.springsecurity6x.security.core.dsl.mfa.configurer;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;

/**
 * Factor DSL 구현체: 개별 인증 스텝별 상세 옵션 설정
 */
public class FactorDslConfigurerImpl implements FactorDslConfigurer {
    private final AuthenticationStepConfig step;

    public FactorDslConfigurerImpl(AuthenticationStepConfig step) {
        this.step = step;
    }

    @Override
    public FactorDslConfigurer type(String factorType) {
        step.type(factorType);
        return this;
    }

    @Override
    public AuthenticationStepConfig toConfig() {
        return step;
    }
}