package io.springsecurity.springsecurity6x.security.core.dsl.impl;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.*;
import org.springframework.security.config.Customizer;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * MFA(다중 인증) 플로우 설정 DSL 구현체
 */
public class MfaDslConfigurerImpl implements MfaDslConfigurer {

    private final List<AuthenticationStepConfig> authConfigs = new ArrayList<>();

    @Override
    public MfaDslConfigurer form(Customizer<FormDslConfigurer> customizer) {
        FormDslConfigurerImpl impl = new FormDslConfigurerImpl();
        customizer.customize(impl);
        authConfigs.add(impl.toConfig());
        return this;
    }

    @Override
    public MfaDslConfigurer rest(Customizer<RestDslConfigurer> customizer) {
        RestDslConfigurerImpl impl = new RestDslConfigurerImpl();
        customizer.customize(impl);
        authConfigs.add(impl.toConfig());
        return this;
    }

    @Override
    public MfaDslConfigurer ott(Customizer<OttDslConfigurer> customizer) {
        OttDslConfigurerImpl impl = new OttDslConfigurerImpl();
        customizer.customize(impl);
        authConfigs.add(impl.toConfig());
        return this;
    }

    @Override
    public MfaDslConfigurer passkey(Customizer<PasskeyDslConfigurer> customizer) {
        PasskeyDslConfigurerImpl impl = new PasskeyDslConfigurerImpl();
        customizer.customize(impl);
        authConfigs.add(impl.toConfig());
        return this;
    }

    /**
     * 구성된 인증 단계 리스트를 반환합니다.
     * @return 인증 단계 구성 리스트
     */
    public List<AuthenticationStepConfig> getAuthConfigs() {
        return authConfigs;
    }
}