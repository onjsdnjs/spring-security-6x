package io.springsecurity.springsecurity6x.security.core.dsl.factor.ott;

import io.springsecurity.springsecurity6x.security.core.dsl.common.AbstractOptionsBuilderConfigurer;
import io.springsecurity.springsecurity6x.security.core.mfa.options.OttFactorOptions;
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
        super(OttFactorOptions.builder()); // OttFactorOptions.Builder 사용
        Assert.notNull(applicationContext, "ApplicationContext cannot be null for OttFactorDslConfigurerImpl if bean lookup is needed.");
        this.applicationContext = applicationContext;
    }

    @Override
    protected OttFactorDslConfigurer self() {
        return this;
    }

    @Override
    public OttFactorDslConfigurer processingUrl(String url) {
        this.optionsBuilder.processingUrl(url);
        return this;
    }

    @Override
    public OttFactorDslConfigurer successHandler(AuthenticationSuccessHandler handler) {
        this.optionsBuilder.successHandler(handler);
        return this;
    }

    @Override
    public OttFactorDslConfigurer failureHandler(AuthenticationFailureHandler handler) {
        this.optionsBuilder.failureHandler(handler);
        return this;
    }

    @Override
    public OttFactorDslConfigurer tokenService(OneTimeTokenService oneTimeTokenService) {
        Assert.notNull(oneTimeTokenService, "oneTimeTokenService cannot be null");
        this.optionsBuilder.oneTimeTokenService(oneTimeTokenService);
        return this;
    }

    @Override
    public OttFactorDslConfigurer tokenServiceBeanName(String beanName) {
        Assert.hasText(beanName, "beanName cannot be empty");
        try {
            OneTimeTokenService service = applicationContext.getBean(beanName, OneTimeTokenService.class);
            this.optionsBuilder.oneTimeTokenService(service);
        } catch (NoSuchBeanDefinitionException e) {
            throw new IllegalArgumentException("No OneTimeTokenService bean found with name: " + beanName, e);
        }
        return this;
    }

    @Override
    public OttFactorDslConfigurer tokenGeneratingUrl(String url) {
        this.optionsBuilder.tokenGeneratingUrl(url);
        return this;
    }

    @Override
    public OttFactorDslConfigurer defaultSubmitPageUrl(String url) {
        this.optionsBuilder.defaultSubmitPageUrl(url); // OttFactorOptions.Builder에 해당 메소드 필요
        return this;
    }

    @Override
    public OttFactorDslConfigurer showDefaultSubmitPage(boolean show) {
        this.optionsBuilder.showDefaultSubmitPage(show); // OttFactorOptions.Builder에 해당 메소드 필요
        return this;
    }

    @Override
    public OttFactorDslConfigurer tokenGenerationSuccessHandler(OneTimeTokenGenerationSuccessHandler handler) {
        this.optionsBuilder.tokenGenerationSuccessHandler(handler); // OttFactorOptions.Builder에 해당 메소드 필요
        return this;
    }

    // buildConcreteOptions()는 AbstractOptionsBuilderConfigurer에서 상속받아 사용
    // @Override
    // public OttFactorOptions buildConcreteOptions() {
    //     // 필요한 Assertions 추가 가능
    //     Assert.notNull(this.optionsBuilder.build().getOneTimeTokenService(), "OneTimeTokenService must be configured for OTT factor.");
    //     // Assert.hasText(this.optionsBuilder.build().getProcessingUrl(), "Processing URL must be set for OTT factor.");
    //     // Assert.hasText(this.optionsBuilder.build().getTokenGeneratingUrl(), "Token generating URL must be set for OTT factor.");
    //     return super.buildConcreteOptions();
    // }
}


