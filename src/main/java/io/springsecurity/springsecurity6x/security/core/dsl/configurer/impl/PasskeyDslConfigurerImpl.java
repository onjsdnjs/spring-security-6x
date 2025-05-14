package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.dsl.common.AbstractOptionsBuilderConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpCustomizer;
import io.springsecurity.springsecurity6x.security.core.dsl.configurer.PasskeyDslConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.PasskeyOptions;
import lombok.extern.slf4j.Slf4j;
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

@Slf4j
public class PasskeyDslConfigurerImpl
        extends AbstractOptionsBuilderConfigurer<PasskeyOptions, PasskeyOptions.Builder, PasskeyDslConfigurer>
        implements PasskeyDslConfigurer {

    public PasskeyDslConfigurerImpl() {
        super(PasskeyOptions.builder());
    }

    @Override
    protected PasskeyDslConfigurer self() {
        return this;
    }

    // PasskeyDslConfigurer 인터페이스에 정의된 메소드들
    @Override
    public PasskeyDslConfigurer rpName(String name) {
        this.optionsBuilder.rpName(name);
        return this;
    }

    @Override
    public PasskeyDslConfigurer rpId(String id) {
        this.optionsBuilder.rpId(id);
        return this;
    }

    @Override
    public PasskeyDslConfigurer allowedOrigins(String... origins) {
        if (origins != null) {
            this.optionsBuilder.allowedOrigins(Arrays.asList(origins)); // PasskeyOptions.Builder는 List<String>을 받을 수 있음
        }
        return this;
    }

    // PasskeyDslConfigurer 인터페이스에 Set<String>을 받는 allowedOrigins도 정의되어 있다면 추가
    public PasskeyDslConfigurer allowedOrigins(Set<String> origins) {
        this.optionsBuilder.allowedOrigins(new ArrayList<>(origins)); // PasskeyOptions.Builder는 List를 받으므로 변환
        return this;
    }


    @Override
    public PasskeyDslConfigurer targetUrl(String targetUrl) {
        this.optionsBuilder.targetUrl(targetUrl);
        return this;
    }

    @Override
    public PasskeyDslConfigurer rawHttp(SafeHttpCustomizer customizer) {
        super.rawHttp(customizer);
        return self();
    }

    @Override
    public PasskeyDslConfigurer disableCsrf() {
        super.disableCsrf();
        return self();
    }

    @Override
    public PasskeyDslConfigurer cors(Customizer<CorsConfigurer<HttpSecurity>> customizer) {
        super.cors(customizer);
        return self();
    }

    @Override
    public PasskeyDslConfigurer headers(Customizer<HeadersConfigurer<HttpSecurity>> customizer) {
        super.headers(customizer);
        return self();
    }

    @Override
    public PasskeyDslConfigurer sessionManagement(Customizer<SessionManagementConfigurer<HttpSecurity>> customizer) {
        super.sessionManagement(customizer);
        return self();
    }

    @Override
    public PasskeyDslConfigurer logout(Customizer<LogoutConfigurer<HttpSecurity>> customizer) {
        super.logout(customizer);
        return self();
    }

    public PasskeyDslConfigurer successHandler(AuthenticationSuccessHandler handler) {
        this.optionsBuilder.successHandler(handler); // PasskeyOptions.Builder에 해당 메소드 필요
        return self();
    }

    public PasskeyDslConfigurer failureHandler(AuthenticationFailureHandler handler) {
        this.optionsBuilder.failureHandler(handler); // PasskeyOptions.Builder에 해당 메소드 필요
        return self();
    }

    @Override
    public PasskeyOptions buildConcreteOptions() {
        // PasskeyOptions.Builder의 build() 메소드에서 필수 값 검증이 이루어져야 함.
        return this.optionsBuilder.build();
    }
}