package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.dsl.common.AbstractOptionsBuilderConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.RecoveryCodeDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.RecoveryCodeOptions;

public class RecoveryCodeDslConfigurerImpl
        extends AbstractOptionsBuilderConfigurer<RecoveryCodeOptions, RecoveryCodeOptions.Builder, RecoveryCodeDslConfigurer>
        implements RecoveryCodeDslConfigurer {

    public RecoveryCodeDslConfigurerImpl() {
        super(RecoveryCodeOptions.builder());
    }


    @Override
    protected RecoveryCodeDslConfigurer self() {
        return this;
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
}
