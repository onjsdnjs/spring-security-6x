package io.springsecurity.springsecurity6x.security.core.dsl.common;

import io.springsecurity.springsecurity6x.security.core.dsl.option.AuthenticationProcessingOptions;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CorsConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;

import java.util.Objects;

public abstract class AbstractOptionsBuilderConfigurer<
        O extends AuthenticationProcessingOptions,
        B extends AuthenticationProcessingOptions.AbstractAuthenticationProcessingOptionsBuilder<O, B>,
        S extends OptionsBuilderDsl<O, S>> implements OptionsBuilderDsl<O, S> {

    protected final B optionsBuilder;

    protected AbstractOptionsBuilderConfigurer(B optionsBuilder) {
        this.optionsBuilder = Objects.requireNonNull(optionsBuilder, "optionsBuilder cannot be null");
    }

    protected B getOptionsBuilder() {
        return this.optionsBuilder;
    }

    protected abstract S self(); // 하위 클래스에서 구체적인 Configurer 타입을 반환하도록 강제

    @Override
    public O buildConcreteOptions() {
        return this.optionsBuilder.build();
    }

    // --- OptionsBuilderDsl Methods Implementation ---
    @Override
    public S loginProcessingUrl(String url) {
        getOptionsBuilder().loginProcessingUrl(url);
        return self();
    }

    @Override
    public S successHandler(AuthenticationSuccessHandler handler) {
        getOptionsBuilder().successHandler(handler);
        return self();
    }

    @Override
    public S failureHandler(AuthenticationFailureHandler handler) {
        getOptionsBuilder().failureHandler(handler);
        return self();
    }

    @Override
    public S securityContextRepository(SecurityContextRepository repository) {
        getOptionsBuilder().securityContextRepository(repository);
        return self();
    }

    // --- CommonSecurityDsl Methods (from AbstractOptions.Builder) ---
    @Override
    public S disableCsrf() {
        getOptionsBuilder().disableCsrf();
        return self();
    }

    @Override
    public S cors(Customizer<CorsConfigurer<HttpSecurity>> customizer) {
        getOptionsBuilder().cors(customizer);
        return self();
    }

    @Override
    public S headers(Customizer<HeadersConfigurer<HttpSecurity>> customizer) {
        getOptionsBuilder().headers(customizer);
        return self();
    }

    @Override
    public S sessionManagement(Customizer<SessionManagementConfigurer<HttpSecurity>> customizer) {
        getOptionsBuilder().sessionManagement(customizer);
        return self();
    }

    @Override
    public S logout(Customizer<LogoutConfigurer<HttpSecurity>> customizer) {
        getOptionsBuilder().logout(customizer);
        return self();
    }

    public S rawHttp(SafeHttpCustomizer customizer) {
        getOptionsBuilder().rawHttp(customizer);
        return self();
    }
}