package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
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
    public PasskeyStepDslConfigurer processingUrl(String url) {
        this.optionsBuilder.processingUrl(url);
        return self();
    }

    @Override
    public PasskeyStepDslConfigurer rpName(String name) {
        this.optionsBuilder.rpName(name);
        return self();
    }

    @Override
    public PasskeyStepDslConfigurer rpId(String id) {
        this.optionsBuilder.rpId(id);
        return self();
    }

    @Override
    public PasskeyStepDslConfigurer allowedOrigins(String... origins) {
        if (origins != null) {
            this.optionsBuilder.allowedOrigins(Arrays.asList(origins));
        } else {
            this.optionsBuilder.allowedOrigins(new ArrayList<>());
        }
        return self();
    }

    @Override
    public PasskeyStepDslConfigurer allowedOrigins(Set<String> origins) {
        if (origins != null) {
            this.optionsBuilder.allowedOrigins(new ArrayList<>(origins));
        } else {
            this.optionsBuilder.allowedOrigins(new ArrayList<>());
        }
        return self();
    }

    @Override
    public PasskeyStepDslConfigurer targetUrl(String url) {
        this.optionsBuilder.targetUrl(url);
        return self();
    }

    @Override
    public PasskeyStepDslConfigurer successHandler(AuthenticationSuccessHandler handler) {
        this.optionsBuilder.successHandler(handler);
        return self();
    }

    @Override
    public PasskeyStepDslConfigurer failureHandler(AuthenticationFailureHandler handler) {
        this.optionsBuilder.failureHandler(handler);
        return self();
    }

    // CommonSecurityDsl methods (from OptionsBuilderDsl)
    @Override
    public PasskeyStepDslConfigurer rawHttp(SafeHttpCustomizer customizer) {
        super.rawHttp(customizer);
        return self();
    }

    @Override
    public PasskeyStepDslConfigurer disableCsrf() {
        super.disableCsrf();
        return self();
    }

    @Override
    public PasskeyStepDslConfigurer cors(Customizer<CorsConfigurer<HttpSecurity>> customizer) {
        super.cors(customizer);
        return self();
    }

    @Override
    public PasskeyStepDslConfigurer headers(Customizer<HeadersConfigurer<HttpSecurity>> customizer) {
        super.headers(customizer);
        return self();
    }

    @Override
    public PasskeyStepDslConfigurer sessionManagement(Customizer<SessionManagementConfigurer<HttpSecurity>> customizer) {
        super.sessionManagement(customizer);
        return self();
    }

    @Override
    public PasskeyStepDslConfigurer logout(Customizer<LogoutConfigurer<HttpSecurity>> customizer) {
        super.logout(customizer);
        return self();
    }

    // order() is part of StepDslConfigurer, not directly handled by OptionsBuilder.
    // This method is here to satisfy the PasskeyStepDslConfigurer interface.
    // The actual order is managed by the AbstractStepAwareDslConfigurer.
    @Override
    public PasskeyStepDslConfigurer order(int order) {
        // This method should ideally not be called on an OptionsBuilderConfigurer.
        // It's a responsibility of the StepAwareConfigurer.
        // Returning self() to fulfill the interface contract.
        return self();
    }

    @Override
    public AuthenticationStepConfig toConfig() {
        return null;
    }

    @Override
    public int getOrder() {
        return 0;
    }
}

