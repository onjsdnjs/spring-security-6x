package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.dsl.common.AbstractOptionsBuilderConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpCustomizer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.PasskeyStepDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.PasskeyOptions;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CorsConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Set;


public class PasskeyDslOptionsBuilderConfigurer
        extends AbstractOptionsBuilderConfigurer<PasskeyOptions, PasskeyOptions.Builder, PasskeyStepDslConfigurer>
        implements PasskeyStepDslConfigurer {

    public PasskeyDslOptionsBuilderConfigurer() {
        super(PasskeyOptions.builder());
    }

    @Override
    protected PasskeyStepDslConfigurer self() {
        return this;
    }

    @Override
    public PasskeyStepDslConfigurer rpName(String name) {
        this.optionsBuilder.rpName(name); return self();
    }
    @Override
    public PasskeyStepDslConfigurer rpId(String id) {
        this.optionsBuilder.rpId(id); return self();
    }
    @Override
    public PasskeyStepDslConfigurer allowedOrigins(String... origins) {
        if (origins != null) this.optionsBuilder.allowedOrigins(Arrays.asList(origins));
        return self();
    }
    @Override
    public PasskeyStepDslConfigurer allowedOrigins(Set<String> origins) {
        if (origins != null) this.optionsBuilder.allowedOrigins(new ArrayList<>(origins));
        return self();
    }
    @Override
    public PasskeyStepDslConfigurer targetUrl(String url) {
        this.optionsBuilder.targetUrl(url); return self();
    }
    @Override
    public PasskeyStepDslConfigurer successHandler(AuthenticationSuccessHandler handler) {
        this.optionsBuilder.successHandler(handler); // PasskeyOptions.Builder에 successHandler 추가 필요
        return self();
    }
    @Override
    public PasskeyStepDslConfigurer failureHandler(AuthenticationFailureHandler handler) {
        this.optionsBuilder.failureHandler(handler); // PasskeyOptions.Builder에 failureHandler 추가 필요
        return self();
    }

    // CommonSecurityDsl 메소드들
    @Override
    public PasskeyStepDslConfigurer rawHttp(SafeHttpCustomizer customizer) {
        super.rawHttp(customizer); return self();
    }
    @Override
    public PasskeyStepDslConfigurer disableCsrf() {
        super.disableCsrf(); return self();
    }
    @Override
    public PasskeyStepDslConfigurer cors(Customizer<CorsConfigurer<HttpSecurity>> customizer) {
        super.cors(customizer); return self();
    }
    @Override
    public PasskeyStepDslConfigurer headers(Customizer<HeadersConfigurer<HttpSecurity>> customizer) {
        super.headers(customizer); return self();
    }
    @Override
    public PasskeyStepDslConfigurer sessionManagement(Customizer<SessionManagementConfigurer<HttpSecurity>> customizer) {
        super.sessionManagement(customizer); return self();
    }
    @Override
    public PasskeyStepDslConfigurer logout(Customizer<LogoutConfigurer<HttpSecurity>> customizer) {
        super.logout(customizer); return self();
    }

    @Override
    public PasskeyStepDslConfigurer order(int order) {
        // OptionsBuilder는 order를 직접 다루지 않음
        return self();
    }
}
