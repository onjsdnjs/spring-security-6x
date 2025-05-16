package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.dsl.common.AbstractOptionsBuilderConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.RestDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.RestOptions;

public class RestDslConfigurerImpl
        extends AbstractOptionsBuilderConfigurer<RestOptions, RestOptions.Builder, RestDslConfigurer>
        implements RestDslConfigurer {

    public RestDslConfigurerImpl() {
        super(RestOptions.builder());
    }

    @Override
    protected RestDslConfigurer self() { // 반환 타입을 RestStepDslConfigurer로 (인터페이스에 맞게)
        return this;
    }

    @Override
    public RestDslConfigurer order(int order) {
        getOptionsBuilder().order(order);
        return this;
    }
}

