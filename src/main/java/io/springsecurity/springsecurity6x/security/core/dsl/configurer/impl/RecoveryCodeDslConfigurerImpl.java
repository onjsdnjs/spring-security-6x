package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.asep.dsl.RestAsepAttributes;
import io.springsecurity.springsecurity6x.security.core.dsl.common.AbstractOptionsBuilderConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.RecoveryCodeDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.RecoveryCodeOptions;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;

public class RecoveryCodeDslConfigurerImpl<H extends HttpSecurityBuilder<H>>
        extends AbstractOptionsBuilderConfigurer<RecoveryCodeDslConfigurerImpl<H>, H, RecoveryCodeOptions, RecoveryCodeOptions.Builder, RecoveryCodeDslConfigurer>
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
    public RecoveryCodeDslConfigurer order(int order) {
        getOptionsBuilder().order(order);
        return  self();
    }

    @Override
    public RecoveryCodeDslConfigurer asep(Customizer<RestAsepAttributes> asepAttributesCustomizer){
        return null;
    }

    @Override
    protected RecoveryCodeDslConfigurerImpl self() {
        return this;
    }

    @Override
    public void configure(H builder) throws Exception {

    }
}
