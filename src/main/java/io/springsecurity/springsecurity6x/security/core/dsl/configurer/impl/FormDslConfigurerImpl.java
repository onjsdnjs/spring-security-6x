package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.asep.dsl.FormAsepAttributes;
import io.springsecurity.springsecurity6x.security.core.dsl.common.AbstractOptionsBuilderConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpFormLoginCustomizer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.FormDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.FormOptions;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;

@Slf4j
public final class FormDslConfigurerImpl<H extends HttpSecurityBuilder<H>>
        extends AbstractOptionsBuilderConfigurer<FormDslConfigurerImpl<H>, H, FormOptions, FormOptions.Builder, FormDslConfigurer>
        implements FormDslConfigurer {

    public FormDslConfigurerImpl() {
        super(FormOptions.builder());
    }

    @Override
    public FormDslConfigurer order(int order) {
        getOptionsBuilder().order(order);
        return self();
    }

    @Override
    public FormDslConfigurer loginPage(String loginPageUrl) {
        getOptionsBuilder().loginPage(loginPageUrl);
        return self();
    }

    @Override
    public FormDslConfigurerImpl<H> loginProcessingUrl(String loginProcessingUrl) {
        getOptionsBuilder().loginProcessingUrl(loginProcessingUrl);
        return self();
    }

    @Override
    public FormDslConfigurer usernameParameter(String usernameParameter) {
        getOptionsBuilder().usernameParameter(usernameParameter);
        return self();
    }

    @Override
    public FormDslConfigurer passwordParameter(String passwordParameter) {
        getOptionsBuilder().passwordParameter(passwordParameter);
        return self();
    }

    @Override
    public FormDslConfigurer defaultSuccessUrl(String defaultSuccessUrl, boolean alwaysUse) {
        getOptionsBuilder().defaultSuccessUrl(defaultSuccessUrl, alwaysUse);
        return self();
    }

    @Override
    public FormDslConfigurer failureUrl(String failureUrl) {
        getOptionsBuilder().failureUrl(failureUrl);
        return self();
    }

    @Override
    public FormDslConfigurer permitAll() {
        getOptionsBuilder().permitAll();
        return self();
    }

    @Override
    public FormDslConfigurerImpl<H> successHandler(AuthenticationSuccessHandler successHandler) {
        getOptionsBuilder().successHandler(successHandler);
        return self();
    }

    @Override
    public FormDslConfigurerImpl<H> failureHandler(AuthenticationFailureHandler failureHandler) {
        getOptionsBuilder().failureHandler(failureHandler);
        return self();
    }

    @Override
    public FormDslConfigurerImpl<H> securityContextRepository(SecurityContextRepository repository) {
        getOptionsBuilder().securityContextRepository(repository);
        return self();
    }

    @Override
    public void configure(HttpSecurityBuilder builder) throws Exception {

    }

    @Override
    public FormDslConfigurer rawFormLogin(SafeHttpFormLoginCustomizer customizer) {
        getOptionsBuilder().rawFormLoginCustomizer(customizer);
        return self();
    }

    @Override
    public FormDslConfigurer asep(Customizer<FormAsepAttributes> formAsepAttributesCustomizer) throws Exception {
        H builder = (H) getBuilder();

        FormAsepAttributes attributes = builder.getSharedObject(FormAsepAttributes.class);
        if (attributes == null) {
            attributes = new FormAsepAttributes();
            log.debug("ASEP: Creating new FormAsepAttributes for HttpSecurityBuilder (hash: {})", System.identityHashCode(builder));
        }

        if (formAsepAttributesCustomizer != null) {
            formAsepAttributesCustomizer.customize(attributes);
            log.debug("ASEP: Customized FormAsepAttributes for HttpSecurityBuilder (hash: {})", System.identityHashCode(builder));
        }

        builder.setSharedObject(FormAsepAttributes.class, attributes);
        log.debug("ASEP: FormAsepAttributes stored/updated in sharedObjects for HttpSecurityBuilder (hash: {})", System.identityHashCode(builder));

        return self();
    }

    protected FormDslConfigurerImpl<H> self(){
        return this;
    }
}