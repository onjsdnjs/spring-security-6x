package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.asep.dsl.BaseAsepAttributes; // 또는 구체적인 ASEP Attributes
import io.springsecurity.springsecurity6x.security.core.dsl.common.AbstractOptionsBuilderConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.RecoveryCodeDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.RecoveryCodeOptions;
import org.springframework.security.config.Customizer; // 추가

public class RecoveryCodeDslConfigurerImpl
        extends AbstractOptionsBuilderConfigurer<RecoveryCodeDslConfigurerImpl, RecoveryCodeOptions, RecoveryCodeOptions.Builder, RecoveryCodeDslConfigurer>
        implements RecoveryCodeDslConfigurer {

    public RecoveryCodeDslConfigurerImpl() {
        super(RecoveryCodeOptions.builder());
    }

    @Override
    public RecoveryCodeDslConfigurer codeLength(int length) {
        getOptionsBuilder().codeLength(length);
        return self();
    }

    @Override
    public RecoveryCodeDslConfigurer numberOfCodesToGenerate(int number) {
        getOptionsBuilder().numberOfCodesToGenerate(number);
        return self();
    }

    @Override
    public RecoveryCodeDslConfigurer emailOtpEndpoint(String endpoint) {
        getOptionsBuilder().emailOtpEndpoint(endpoint);
        return self();
    }

    @Override
    public RecoveryCodeDslConfigurer smsOtpEndpoint(String endpoint) {
        getOptionsBuilder().smsOtpEndpoint(endpoint);
        return self();
    }

    @Override
    public RecoveryCodeDslConfigurer order(int order) {
        getOptionsBuilder().order(order); // RecoveryCodeOptions.Builder에 order() 메서드 추가 필요
        return self();
    }

    @Override
    public RecoveryCodeDslConfigurer asep(Customizer<BaseAsepAttributes> asepAttributesCustomizer) {
        // RecoveryCodeOptions.Builder에 asepAttributes(BaseAsepAttributes) 메서드 추가 필요
        // BaseAsepAttributes attributes = new BaseAsepAttributesImpl(); // BaseAsepAttributes의 구체적 구현 필요
        // if (asepAttributesCustomizer != null) {
        //     asepAttributesCustomizer.customize(attributes);
        // }
        // getOptionsBuilder().asepAttributes(attributes);
        return self();
    }

    @Override
    protected RecoveryCodeDslConfigurerImpl self() {
        return this;
    }
}
