package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.dsl.common.AbstractOptionsBuilderConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.PasskeyDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.PasskeyOptions;

import java.util.List;
import java.util.Set;

public class PasskeyDslConfigurerImpl
        extends AbstractOptionsBuilderConfigurer<PasskeyOptions, PasskeyOptions.Builder, PasskeyDslConfigurer>
        implements PasskeyDslConfigurer {

    public PasskeyDslConfigurerImpl() {
        super(PasskeyOptions.builder());
    }

    @Override
    protected PasskeyDslConfigurer self() {
        return this;
    }

    @Override
    public PasskeyDslConfigurer order(int order) {
        getOptionsBuilder().order(order);
        return this;
    }

    @Override
    public PasskeyDslConfigurer assertionOptionsEndpoint(String url) {
        getOptionsBuilder().assertionOptionsEndpoint(url);
        return self();
    }

    @Override
    public PasskeyDslConfigurer rpName(String rpName) {
        getOptionsBuilder().rpName(rpName);
        return self();
    }

    @Override
    public PasskeyDslConfigurer rpId(String rpId) {
        getOptionsBuilder().rpId(rpId);
        return self();
    }

    @Override
    public PasskeyDslConfigurer allowedOrigins(List<String> origins) {
        getOptionsBuilder().allowedOrigins(origins);
        return self();
    }

    @Override
    public PasskeyDslConfigurer allowedOrigins(String... origins) {
        getOptionsBuilder().allowedOrigins(origins);
        return self();
    }

    @Override
    public PasskeyDslConfigurer allowedOrigins(Set<String> origins) {
        getOptionsBuilder().allowedOrigins(origins);
        return self();
    }
}
