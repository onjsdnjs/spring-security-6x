package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.dsl.common.AbstractOptionsBuilderConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpFormLoginCustomizer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.FormDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.FormOptions;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;

public class FormDslOptionsBuilderConfigurer
        extends AbstractOptionsBuilderConfigurer<FormOptions, FormOptions.Builder, FormDslConfigurer>
        implements FormDslConfigurer {

    public FormDslOptionsBuilderConfigurer() {
        super(FormOptions.builder());
    }

    @Override
    protected FormDslConfigurer self() { return this; }

    @Override
    public FormDslConfigurer loginPage(String loginPageUrl) {
        this.optionsBuilder.loginPage(loginPageUrl); return self();
    }
    @Override
    public FormDslConfigurer loginProcessingUrl(String loginProcessingUrl) {
        this.optionsBuilder.loginProcessingUrl(loginProcessingUrl); return self();
    }
    @Override
    public FormDslConfigurer usernameParameter(String usernameParameter) {
        this.optionsBuilder.usernameParameter(usernameParameter); return self();
    }
    @Override
    public FormDslConfigurer passwordParameter(String passwordParameter) {
        this.optionsBuilder.passwordParameter(passwordParameter); return self();
    }
    @Override
    public FormDslConfigurer defaultSuccessUrl(String defaultSuccessUrl, boolean alwaysUse) {
        this.optionsBuilder.defaultSuccessUrl(defaultSuccessUrl, alwaysUse); return self();
    }
    @Override
    public FormDslConfigurer failureUrl(String failureUrl) {
        this.optionsBuilder.failureUrl(failureUrl); return self();
    }
    @Override
    public FormDslConfigurer permitAll() {
        this.optionsBuilder.isPermitAll(); return self();
    }
    @Override
    public FormDslConfigurer successHandler(AuthenticationSuccessHandler successHandler) {
        this.optionsBuilder.successHandler(successHandler); return self();
    }
    @Override
    public FormDslConfigurer failureHandler(AuthenticationFailureHandler failureHandler) {
        this.optionsBuilder.failureHandler(failureHandler); return self();
    }
    @Override
    public FormDslConfigurer securityContextRepository(SecurityContextRepository repository) {
        this.optionsBuilder.securityContextRepository(repository); return self();
    }
    @Override
    public FormDslConfigurer rawLogin(SafeHttpFormLoginCustomizer customizer) {
        this.optionsBuilder.rawFormLogin(wrapSafeFormLoginCustomizer(customizer)); return self();
    }
}
