package io.springsecurity.springsecurity6x.security.core.dsl.factor.ott;

import io.springsecurity.springsecurity6x.security.core.mfa.options.ott.OttFactorOptions;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.Assert;


public class OttFactorDslConfigurerImpl implements OttFactorDslConfigurer {
    private final ApplicationContext applicationContext; // Spring 빈(OneTimeTokenService) 조회를 위해 필요
    private final OttFactorOptions options = new OttFactorOptions();

    public OttFactorDslConfigurerImpl(ApplicationContext applicationContext) {
        Assert.notNull(applicationContext, "ApplicationContext cannot be null for OttFactorDslConfigurerImpl if bean lookup is needed.");
        this.applicationContext = applicationContext;
    }

    @Override
    public OttFactorDslConfigurer processingUrl(String url) {
        this.options.setProcessingUrl(url);
        return this;
    }

    @Override
    public OttFactorDslConfigurer successHandler(AuthenticationSuccessHandler handler) {
        this.options.setSuccessHandler(handler);
        return this;
    }

    @Override
    public OttFactorDslConfigurer failureHandler(AuthenticationFailureHandler handler) {
        this.options.setFailureHandler(handler);
        return this;
    }

    @Override
    public OttFactorDslConfigurer tokenService(OneTimeTokenService oneTimeTokenService) {
        Assert.notNull(oneTimeTokenService, "oneTimeTokenService cannot be null");
        this.options.setOneTimeTokenService(oneTimeTokenService);
        return this;
    }

    @Override
    public OttFactorDslConfigurer tokenServiceBeanName(String beanName) {
        Assert.hasText(beanName, "beanName cannot be empty");
        try {
            this.options.setOneTimeTokenService(applicationContext.getBean(beanName, OneTimeTokenService.class));
        } catch (NoSuchBeanDefinitionException e) {
            throw new IllegalArgumentException("No OneTimeTokenService bean found with name: " + beanName, e);
        }
        return this;
    }

    @Override
    public OttFactorDslConfigurer tokenGeneratingUrl(String url) {
        this.options.setTokenGeneratingUrl(url);
        return this;
    }

    @Override
    public OttFactorOptions buildAuthenticationOptions() {
        Assert.notNull(options.getOneTimeTokenService(), "OneTimeTokenService must be configured for OTT factor.");
        Assert.hasText(options.getProcessingUrl(), "Processing URL must be set for OTT factor.");
        Assert.hasText(options.getTokenGeneratingUrl(), "Token generating URL must be set for OTT factor.");
        return this.options;
    }
}


