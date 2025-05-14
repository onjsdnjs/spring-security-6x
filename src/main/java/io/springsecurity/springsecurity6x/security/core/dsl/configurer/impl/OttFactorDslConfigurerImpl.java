package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.dsl.common.AbstractOptionsBuilderConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.factor.ott.OttFactorDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.mfa.options.ott.OttFactorOptions;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.util.Assert;

public class OttFactorDslConfigurerImpl
        extends AbstractOptionsBuilderConfigurer<OttFactorOptions, OttFactorOptions.Builder, OttFactorDslConfigurer>
        implements OttFactorDslConfigurer {

    private final ApplicationContext applicationContext;

    public OttFactorDslConfigurerImpl(ApplicationContext applicationContext) {
        super(OttFactorOptions.builder()); // OttFactorOptions에 Builder 추가 필요
        this.applicationContext = applicationContext;
    }

    @Override
    protected OttFactorDslConfigurer self() { return this; }

    @Override
    public OttFactorDslConfigurer processingUrl(String url) {
        this.optionsBuilder.processingUrl(url); return self();
    }
    @Override
    public OttFactorDslConfigurer successHandler(AuthenticationSuccessHandler handler) {
        this.optionsBuilder.successHandler(handler); return self();
    }
    @Override
    public OttFactorDslConfigurer failureHandler(AuthenticationFailureHandler handler) {
        this.optionsBuilder.failureHandler(handler); return self();
    }

    @Override
    public OttFactorDslConfigurer tokenService(OneTimeTokenService oneTimeTokenService) {
        Assert.notNull(oneTimeTokenService, "oneTimeTokenService cannot be null");
        this.optionsBuilder.oneTimeTokenService(oneTimeTokenService); // OttFactorOptions.Builder에 추가
        return this;
    }

    @Override
    public OttFactorDslConfigurer tokenServiceBeanName(String beanName) {
        Assert.hasText(beanName, "beanName cannot be empty");
        try {
            this.optionsBuilder.oneTimeTokenService(applicationContext.getBean(beanName, OneTimeTokenService.class));
        } catch (NoSuchBeanDefinitionException e) {
            throw new IllegalArgumentException("No OneTimeTokenService bean found with name: " + beanName, e);
        }
        return this;
    }

    @Override
    public OttFactorDslConfigurer tokenGeneratingUrl(String url) {
        this.optionsBuilder.tokenGeneratingUrl(url); // OttFactorOptions.Builder에 추가
        return this;
    }

    @Override
    public OttFactorDslConfigurer tokenGenerationSuccessHandler(OneTimeTokenGenerationSuccessHandler handler) {
        this.optionsBuilder.tokenGenerationSuccessHandler(handler); // OttFactorOptions.Builder에 추가
        return this;
    }
}