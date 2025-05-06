package io.springsecurity.springsecurity6x.security.core.dsl.impl;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.FormDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.common.AbstractDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.feature.option.FormOptions;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.function.ThrowingConsumer;

import java.util.Arrays;


/**
 * Form 로그인 DSL 구현체
 */
public class FormDslConfigurerImpl extends AbstractDslConfigurer<FormOptions.Builder, FormDslConfigurer> implements FormDslConfigurer {

    public FormDslConfigurerImpl(AuthenticationStepConfig stepConfig) {
        super(stepConfig, FormOptions.builder());
    }

    @Override
    public FormDslConfigurer matchers(String... patterns) {
        options.matchers(Arrays.asList(patterns));
        return this;
    }

    @Override
    public FormDslConfigurer loginPage(String loginPageUrl) {
        options.loginPage(loginPageUrl);
        return this;
    }

    @Override
    public FormDslConfigurer loginProcessingUrl(String loginProcessingUrl) {
        options.loginProcessingUrl(loginProcessingUrl);
        return this;
    }

    @Override
    public FormDslConfigurer usernameParameter(String usernameParameter) {
        options.usernameParameter(usernameParameter);
        return this;
    }

    @Override
    public FormDslConfigurer passwordParameter(String passwordParameter) {
        options.passwordParameter(passwordParameter);
        return this;
    }

    @Override
    public FormDslConfigurer defaultSuccessUrl(String defaultSuccessUrl, boolean alwaysUse) {
        options.defaultSuccessUrl(defaultSuccessUrl, alwaysUse);
        return this;
    }

    @Override
    public FormDslConfigurer failureUrl(String failureUrl) {
        options.failureUrl(failureUrl);
        return this;
    }

    @Override
    public FormDslConfigurer permitAll() {
        options.permitAll();
        return this;
    }

    @Override
    public FormDslConfigurer successHandler(AuthenticationSuccessHandler successHandler) {
        options.successHandler(successHandler);
        return this;
    }

    @Override
    public FormDslConfigurer failureHandler(AuthenticationFailureHandler failureHandler) {
        options.failureHandler(failureHandler);
        return this;
    }

    @Override
    public FormDslConfigurer securityContextRepository(SecurityContextRepository repo) {
        options.securityContextRepository(repo);
        return this;
    }

    @Override
    public FormDslConfigurer raw(Customizer<FormLoginConfigurer<HttpSecurity>> customizer) {
        options.raw(customizer);
        return this;
    }

    /**
     * AuthenticationStepConfig 생성 및 옵션 저장
     */
    public AuthenticationStepConfig toConfig() {
        FormOptions optsBuilt = options.build();
        AuthenticationStepConfig step = getStepConfig();
        step.setType("form");
        step.setMatchers(optsBuilt.getMatchers().toArray(new String[0]));
        step.getOptions().put("_options", optsBuilt);
        return step;
    }
}