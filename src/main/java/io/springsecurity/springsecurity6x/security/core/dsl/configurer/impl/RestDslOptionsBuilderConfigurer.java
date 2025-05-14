package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.dsl.common.AbstractOptionsBuilderConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.RestDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.RestOptions;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;

public class RestDslOptionsBuilderConfigurer
        extends AbstractOptionsBuilderConfigurer<RestOptions, RestOptions.Builder, RestDslConfigurer>
        implements RestDslConfigurer {

    public RestDslOptionsBuilderConfigurer() {
        super(RestOptions.builder());
    }

    @Override
    protected RestDslConfigurer self() { return this; }

    @Override
    public RestDslConfigurer loginProcessingUrl(String url) {
        this.optionsBuilder.loginProcessingUrl(url); return self();
    }
    @Override
    public RestDslConfigurer targetUrl(String url) {
        this.optionsBuilder.targetUrl(url); return self();
    }
    @Override
    public RestDslConfigurer successHandler(AuthenticationSuccessHandler handler) {
        this.optionsBuilder.successHandler(handler); return self();
    }
    @Override
    public RestDslConfigurer failureHandler(AuthenticationFailureHandler handler) {
        this.optionsBuilder.failureHandler(handler); return self();
    }
    @Override
    public RestDslConfigurer securityContextRepository(SecurityContextRepository repository) {
        this.optionsBuilder.securityContextRepository(repository); return self();
    }
}
