package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.common.AbstractStepAwareDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpCustomizer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.RestStepDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.RestOptions;
import io.springsecurity.springsecurity6x.security.core.mfa.options.RestFactorOptions;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CorsConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;

public class RestDslConfigurerImpl
        extends AbstractStepAwareDslConfigurer<
        RestOptions,
        RestOptions.Builder,
        RestDslOptionsBuilderConfigurer,
        RestStepDslConfigurer> implements RestStepDslConfigurer {

    public RestDslConfigurerImpl(AuthenticationStepConfig stepConfig) {
        super(stepConfig, new RestDslOptionsBuilderConfigurer());
    }

    @Override
    protected String getAuthTypeName() {
        return AuthType.REST.name().toLowerCase();
    }

    @Override
    protected RestStepDslConfigurer self() {
        return this;
    }

    // RestDslConfigurer (OptionsBuilderDsl) 메소드 위임
    @Override
    public RestStepDslConfigurer loginProcessingUrl(String url) {
        this.optionsConfigurerImpl.loginProcessingUrl(url); return self();
    }
    @Override
    public RestStepDslConfigurer targetUrl(String url) {
        this.optionsConfigurerImpl.targetUrl(url); return self();
    }
    @Override
    public RestStepDslConfigurer successHandler(AuthenticationSuccessHandler handler) {
        this.optionsConfigurerImpl.successHandler(handler); return self();
    }
    @Override
    public RestStepDslConfigurer failureHandler(AuthenticationFailureHandler handler) {
        this.optionsConfigurerImpl.failureHandler(handler); return self();
    }
    @Override
    public RestStepDslConfigurer securityContextRepository(SecurityContextRepository repository) {
        this.optionsConfigurerImpl.securityContextRepository(repository); return self();
    }

    // CommonSecurityDsl 부분 위임
    @Override
    public RestStepDslConfigurer rawHttp(SafeHttpCustomizer customizer) {
        this.optionsConfigurerImpl.rawHttp(customizer); return self();
    }
    @Override
    public RestStepDslConfigurer disableCsrf() {
        this.optionsConfigurerImpl.disableCsrf(); return self();
    }
    @Override
    public RestStepDslConfigurer cors(Customizer<CorsConfigurer<HttpSecurity>> customizer) {
        this.optionsConfigurerImpl.cors(customizer); return self();
    }
    @Override
    public RestStepDslConfigurer headers(Customizer<HeadersConfigurer<HttpSecurity>> customizer) {
        this.optionsConfigurerImpl.headers(customizer); return self();
    }
    @Override
    public RestStepDslConfigurer sessionManagement(Customizer<SessionManagementConfigurer<HttpSecurity>> customizer) {
        this.optionsConfigurerImpl.sessionManagement(customizer); return self();
    }
    @Override
    public RestStepDslConfigurer logout(Customizer<LogoutConfigurer<HttpSecurity>> customizer) {
        this.optionsConfigurerImpl.logout(customizer); return self();
    }

    @Override
    public RestFactorOptions buildConcreteOptions() {
        return null;
    }

    @Override
    public RestStepDslConfigurer order(int orderValue) {
        super.order(orderValue);
        return self();
    }
}

