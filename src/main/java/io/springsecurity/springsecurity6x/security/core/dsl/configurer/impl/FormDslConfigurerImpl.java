package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.dsl.common.AbstractOptionsBuilderConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpFormLoginCustomizer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.FormDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.FormOptions;
import org.springframework.security.web.context.SecurityContextRepository;

public class FormDslConfigurerImpl
        extends AbstractOptionsBuilderConfigurer<FormOptions, FormOptions.Builder, FormDslConfigurer>
        implements FormDslConfigurer {

    public FormDslConfigurerImpl() {
        super(FormOptions.builder());
    }

    @Override
    protected FormDslConfigurer self() {
        return this;
    }

    @Override
    public FormDslConfigurer loginPage(String loginPageUrl) {
        getOptionsBuilder().loginPage(loginPageUrl); return self();
    }
   
    @Override
    public FormDslConfigurer usernameParameter(String usernameParameter) {
        getOptionsBuilder().usernameParameter(usernameParameter); return self();
    }
    @Override
    public FormDslConfigurer passwordParameter(String passwordParameter) {
        getOptionsBuilder().passwordParameter(passwordParameter); return self();
    }
    @Override
    public FormDslConfigurer defaultSuccessUrl(String defaultSuccessUrl, boolean alwaysUse) {
        getOptionsBuilder().defaultSuccessUrl(defaultSuccessUrl, alwaysUse); return self();
    }
    @Override
    public FormDslConfigurer failureUrl(String failureUrl) {
        getOptionsBuilder().failureUrl(failureUrl); return self();
    }
    @Override
    public FormDslConfigurer permitAll() {
        getOptionsBuilder().permitAll(); return self();
    }

    @Override
    public FormDslConfigurer securityContextRepository(SecurityContextRepository repository) {
        getOptionsBuilder().securityContextRepository(repository); return self();
    }
    @Override
    public FormDslConfigurer rawFormLogin(SafeHttpFormLoginCustomizer customizer) {
        getOptionsBuilder().rawFormLogin(customizer); return self();
    }
}