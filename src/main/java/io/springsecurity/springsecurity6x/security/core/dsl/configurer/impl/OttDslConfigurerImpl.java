package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.dsl.common.AbstractOptionsBuilderConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.OttDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.OttOptions;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;

public class OttDslConfigurerImpl
        extends AbstractOptionsBuilderConfigurer<OttOptions, OttOptions.Builder, OttDslConfigurer>
        implements OttDslConfigurer {

    public OttDslConfigurerImpl(ApplicationContext applicationContext) {
        super(OttOptions.builder(applicationContext));
    }

    @Override
    protected OttDslConfigurer self() {
        return this;
    }

    @Override
    public OttDslConfigurer defaultSubmitPageUrl(String url) {
        getOptionsBuilder().defaultSubmitPageUrl(url); return self();
    }

    @Override
    public OttDslConfigurer tokenGeneratingUrl(String url) {
        getOptionsBuilder().tokenGeneratingUrl(url); return self();
    }

    @Override
    public OttDslConfigurer showDefaultSubmitPage(boolean show) {
        getOptionsBuilder().showDefaultSubmitPage(show); return self();
    }

    @Override
    public OttDslConfigurer tokenService(OneTimeTokenService service) {
        getOptionsBuilder().oneTimeTokenService(service); return self();
    }

    @Override
    public OttDslConfigurer tokenGenerationSuccessHandler(OneTimeTokenGenerationSuccessHandler handler) {
        getOptionsBuilder().tokenGenerationSuccessHandler(handler); return self();
    }
}

