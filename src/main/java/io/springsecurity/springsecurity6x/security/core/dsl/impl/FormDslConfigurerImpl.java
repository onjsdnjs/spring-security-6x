package io.springsecurity.springsecurity6x.security.core.dsl.impl;

import io.springsecurity.springsecurity6x.security.core.dsl.FormDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.common.AbstractDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.feature.option.FormOptions;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.function.ThrowingConsumer;

import java.util.List;

/**
 * Form 로그인 DSL 구현체
 */
public class FormDslConfigurerImpl extends AbstractDslConfigurer<FormDslConfigurerImpl> implements FormDslConfigurer {

    private final FormOptions.Builder opts = FormOptions.builder();

    @Override
    public FormDslConfigurerImpl matchers(String... patterns) {
        opts.matchers(List.of(patterns));
        return self();
    }

    @Override
    public FormDslConfigurerImpl loginPage(String url) {
        opts.loginPage(url);
        return self();
    }

    @Override
    public FormDslConfigurerImpl loginProcessingUrl(String url) {
        opts.loginProcessingUrl(url);
        return self();
    }

    @Override
    public FormDslConfigurerImpl usernameParameter(String param) {
        opts.usernameParameter(param);
        return self();
    }

    @Override
    public FormDslConfigurerImpl passwordParameter(String param) {
        opts.passwordParameter(param);
        return self();
    }

    @Override
    public FormDslConfigurerImpl defaultSuccessUrl(String url, boolean alwaysUse) {
        opts.defaultSuccessUrl(url, alwaysUse);
        return self();
    }

    @Override
    public FormDslConfigurerImpl failureUrl(String url) {
        opts.failureUrl(url);
        return self();
    }

    @Override
    public FormDslConfigurerImpl successHandler(AuthenticationSuccessHandler h) {
        opts.successHandler(h);
        return self();
    }

    @Override
    public FormDslConfigurerImpl failureHandler(AuthenticationFailureHandler h) {
        opts.failureHandler(h);
        return self();
    }

    @Override
    public FormDslConfigurerImpl securityContextRepository(SecurityContextRepository repo) {
        opts.securityContextRepository(repo);
        return self();
    }

    public AuthenticationStepConfig toConfig() {
        FormOptions options = opts.build();
        AuthenticationStepConfig step = new AuthenticationStepConfig();
        step.setType("form");
        if (!options.getMatchers().isEmpty()) {
            step.setMatchers(options.getMatchers().toArray(new String[0]));
        }
        // Store options object
        step.getOptions().put("_options", options);
        return step;
    }

    public ThrowingConsumer<HttpSecurity> toFlowCustomizer() {
        return http -> applyCommon(http);
    }
}

