package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.common.AbstractStepAwareDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpCustomizer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.PasskeyStepDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.PasskeyOptions;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CorsConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.util.Set;

@Slf4j
public class PasskeyDslConfigurerImpl
        extends AbstractStepAwareDslConfigurer<
        PasskeyOptions,                             // O - Options type
        PasskeyOptions.Builder,                     // B - Options Builder type
        PasskeyDslOptionsBuilderConfigurer,         // OBI - Options Builder Configurer Implementation
        PasskeyStepDslConfigurer                    // S - Self-type (the StepDslConfigurer interface)
        >
        implements PasskeyStepDslConfigurer {

    public PasskeyDslConfigurerImpl(AuthenticationStepConfig stepConfig) {
        // PasskeyDslOptionsBuilderConfigurer 인스턴스를 생성하여 부모 생성자에 전달합니다.
        super(stepConfig, new PasskeyDslOptionsBuilderConfigurer());
    }

    @Override
    protected String getAuthTypeName() {
        return AuthType.PASSKEY.name().toLowerCase();
    }

    @Override
    protected PasskeyStepDslConfigurer self() {
        return this;
    }

    // --- PasskeyStepDslConfigurer Methods (Delegated to optionsConfigurerImpl) ---
    @Override
    public PasskeyStepDslConfigurer processingUrl(String url) {
        // this.optionsConfigurerImpl는 PasskeyDslOptionsBuilderConfigurer 타입이며,
        // 이 클래스는 PasskeyStepDslConfigurer 인터페이스를 구현하므로 processingUrl 메소드를 가짐.
        this.optionsConfigurerImpl.processingUrl(url);
        return self();
    }

    @Override
    public PasskeyStepDslConfigurer rpName(String name) {
        this.optionsConfigurerImpl.rpName(name);
        return self();
    }

    @Override
    public PasskeyStepDslConfigurer rpId(String id) {
        this.optionsConfigurerImpl.rpId(id);
        return self();
    }

    @Override
    public PasskeyStepDslConfigurer allowedOrigins(String... origins) {
        this.optionsConfigurerImpl.allowedOrigins(origins);
        return self();
    }

    @Override
    public PasskeyStepDslConfigurer allowedOrigins(Set<String> origins) {
        this.optionsConfigurerImpl.allowedOrigins(origins);
        return self();
    }

    @Override
    public PasskeyStepDslConfigurer targetUrl(String url) {
        this.optionsConfigurerImpl.targetUrl(url);
        return self();
    }

    @Override
    public PasskeyStepDslConfigurer successHandler(AuthenticationSuccessHandler handler) {
        this.optionsConfigurerImpl.successHandler(handler);
        return self();
    }

    @Override
    public PasskeyStepDslConfigurer failureHandler(AuthenticationFailureHandler handler) {
        this.optionsConfigurerImpl.failureHandler(handler);
        return self();
    }

    // --- OptionsBuilderDsl Common Methods (Delegated to optionsConfigurerImpl via super or directly) ---
    @Override
    public PasskeyStepDslConfigurer rawHttp(SafeHttpCustomizer customizer) {
        this.optionsConfigurerImpl.rawHttp(customizer); // AbstractOptionsBuilderConfigurer에 구현된 메소드 호출
        return self();
    }

    @Override
    public PasskeyStepDslConfigurer disableCsrf() {
        this.optionsConfigurerImpl.disableCsrf();
        return self();
    }

    @Override
    public PasskeyStepDslConfigurer cors(Customizer<CorsConfigurer<HttpSecurity>> customizer) {
        this.optionsConfigurerImpl.cors(customizer);
        return self();
    }

    @Override
    public PasskeyStepDslConfigurer headers(Customizer<HeadersConfigurer<HttpSecurity>> customizer) {
        this.optionsConfigurerImpl.headers(customizer);
        return self();
    }

    @Override
    public PasskeyStepDslConfigurer sessionManagement(Customizer<SessionManagementConfigurer<HttpSecurity>> customizer) {
        this.optionsConfigurerImpl.sessionManagement(customizer);
        return self();
    }

    @Override
    public PasskeyStepDslConfigurer logout(Customizer<LogoutConfigurer<HttpSecurity>> customizer) {
        this.optionsConfigurerImpl.logout(customizer);
        return self();
    }

    // --- Methods from OptionsBuilderDsl (Implemented by AbstractOptionsBuilderConfigurer via optionsConfigurerImpl) ---
    @Override
    public PasskeyOptions buildConcreteOptions() {
        return this.optionsConfigurerImpl.buildConcreteOptions();
    }

    // --- Methods from StepDslConfigurer (Implemented by AbstractStepAwareDslConfigurer) ---
    @Override
    public PasskeyStepDslConfigurer order(int orderValue) {
        super.order(orderValue); // AbstractStepAwareDslConfigurer의 order 메소드 호출
        return self();
    }

    // getOrder() and toConfig() are inherited from AbstractStepAwareDslConfigurer
    // public int getOrder() { return super.getOrder(); }
    // public AuthenticationStepConfig toConfig() { return super.toConfig(); }
}
