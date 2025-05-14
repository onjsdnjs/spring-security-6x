package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.common.AbstractStepAwareDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpCustomizer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.OttStepDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.OttOptions;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CorsConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;

public class OttDslConfigurerImpl
        extends AbstractStepAwareDslConfigurer<OttOptions, OttOptions.Builder, OttDslOptionsBuilderConfigurer, OttStepDslConfigurer>
        implements OttStepDslConfigurer { // 인터페이스 변경

    public OttDslConfigurerImpl(AuthenticationStepConfig stepConfig, ApplicationContext applicationContext) {
        super(stepConfig, new OttDslOptionsBuilderConfigurer(applicationContext)); // OptionsBuilderConfigurer에 context 전달
        // this.applicationContext = applicationContext; // 더 이상 필드로 가질 필요 없음
    }

    @Override
    protected String getAuthTypeName() {
        return AuthType.OTT.name().toLowerCase();
    }

    @Override
    protected OttStepDslConfigurer self() {
        return this;
    }

    // --- OttStepDslConfigurer 메소드 구현 (optionsConfigurerImpl에 위임) ---
    @Override
    public OttStepDslConfigurer loginProcessingUrl(String url) {
        this.optionsConfigurerImpl.loginProcessingUrl(url); return self();
    }

    @Override
    public OttStepDslConfigurer targetUrl(String url) {
        this.optionsConfigurerImpl.targetUrl(url); return self();
    }

    @Override
    public OttStepDslConfigurer defaultSubmitPageUrl(String url) {
        this.optionsConfigurerImpl.defaultSubmitPageUrl(url); return self();
    }

    @Override
    public OttStepDslConfigurer tokenGeneratingUrl(String url) {
        this.optionsConfigurerImpl.tokenGeneratingUrl(url); return self();
    }

    @Override
    public OttStepDslConfigurer showDefaultSubmitPage(boolean show) {
        this.optionsConfigurerImpl.showDefaultSubmitPage(show); return self();
    }

    @Override
    public OttStepDslConfigurer tokenService(OneTimeTokenService service) {
        this.optionsConfigurerImpl.tokenService(service); return self();
    }

    @Override
    public OttStepDslConfigurer tokenServiceBeanName(String beanName) {
        this.optionsConfigurerImpl.tokenServiceBeanName(beanName);
        return self();
    }

    @Override
    public OttStepDslConfigurer tokenGenerationSuccessHandler(OneTimeTokenGenerationSuccessHandler handler) {
        this.optionsConfigurerImpl.tokenGenerationSuccessHandler(handler); return self();
    }

    @Override
    public OttStepDslConfigurer rawHttp(SafeHttpCustomizer customizer) {
        this.optionsConfigurerImpl.rawHttp(customizer); return self();
    }
    @Override
    public OttStepDslConfigurer disableCsrf() {
        this.optionsConfigurerImpl.disableCsrf(); return self();
    }
    @Override
    public OttStepDslConfigurer cors(Customizer<CorsConfigurer<HttpSecurity>> customizer) {
        this.optionsConfigurerImpl.cors(customizer); return self();
    }
    @Override
    public OttStepDslConfigurer headers(Customizer<HeadersConfigurer<HttpSecurity>> customizer) {
        this.optionsConfigurerImpl.headers(customizer); return self();
    }
    @Override
    public OttStepDslConfigurer sessionManagement(Customizer<SessionManagementConfigurer<HttpSecurity>> customizer) {
        this.optionsConfigurerImpl.sessionManagement(customizer); return self();
    }
    @Override
    public OttStepDslConfigurer logout(Customizer<LogoutConfigurer<HttpSecurity>> customizer) {
        this.optionsConfigurerImpl.logout(customizer); return self();
    }

    @Override
    public OttOptions buildConcreteOptions() {
        return this.optionsConfigurerImpl.buildConcreteOptions();
    }

    @Override
    public OttStepDslConfigurer order(int orderValue) {
        super.order(orderValue);
        return self();
    }
}

