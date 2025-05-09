package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.RestDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.AbstractDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpCustomizer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.RestOptions;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.function.ThrowingConsumer;

public class RestDslConfigurerImpl extends AbstractDslConfigurer<RestOptions.Builder, RestDslConfigurer> implements RestDslConfigurer {

    public RestDslConfigurerImpl(AuthenticationStepConfig stepConfig) {
        super(stepConfig, RestOptions.builder());
    }

    @Override
    public RestDslConfigurer order(int order) {
        this.order = order;
        return this;
    }

    @Override
    public int order() {
        return order;
    }

    @Override
    public RestDslConfigurer loginProcessingUrl(String loginProcessingUrl) {
        options.loginProcessingUrl(loginProcessingUrl);
        return this;
    }

    @Override
    public RestDslConfigurer successHandler(AuthenticationSuccessHandler handler) {
        options.successHandler(handler);
        return this;
    }

    @Override
    public RestDslConfigurer failureHandler(AuthenticationFailureHandler handler) {
        options.failureHandler(handler);
        return this;
    }

    @Override
    public RestDslConfigurer securityContextRepository(SecurityContextRepository repository) {
        options.securityContextRepository(repository);
        return this;
    }

    @Override
    public RestDslConfigurer raw(SafeHttpCustomizer customizer) {
        return originRaw(wrapSafe(customizer));
    }

    public RestDslConfigurer originRaw(Customizer<HttpSecurity> customizer) {
        options.rawHttp(customizer);
        return this;
    }

    private Customizer<HttpSecurity> wrapSafe(SafeHttpCustomizer safe) {
        return http -> {
            try {
                safe.customize(http);
            } catch (Exception e) {
                System.err.println("Rest customizer exception: " + e.getMessage());
            }
        };
    }

    @Override
    public ThrowingConsumer<HttpSecurity> toFlowCustomizer() {
        return http -> {
            RestOptions optsBuilt = options.build();
            try {
                optsBuilt.applyCommon(http);
            } catch (Exception e) {
                // 예외는 내부에서 처리, 로그를 남기거나 무시
            }
        };
    }

    public AuthenticationStepConfig toConfig() {
        RestOptions optsBuilt = options.build();
        AuthenticationStepConfig step = stepConfig();
        step.type("rest");
        step.options().put("_options", optsBuilt);
        return step;
    }
}

