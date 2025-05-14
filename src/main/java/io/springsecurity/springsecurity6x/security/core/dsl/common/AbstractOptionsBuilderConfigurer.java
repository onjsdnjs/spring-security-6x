package io.springsecurity.springsecurity6x.security.core.dsl.common;

import io.springsecurity.springsecurity6x.security.core.dsl.option.AbstractOptions;
import io.springsecurity.springsecurity6x.security.exception.DslConfigurationException;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CorsConfigurer;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import java.util.Objects;

public abstract class AbstractOptionsBuilderConfigurer<
        O extends AbstractOptions,
        B extends AbstractOptions.Builder<O, B>,
        S extends OptionsBuilderDsl<O, S>> implements OptionsBuilderDsl<O, S> {

    protected final B optionsBuilder;

    protected AbstractOptionsBuilderConfigurer(B optionsBuilder) {
        this.optionsBuilder = Objects.requireNonNull(optionsBuilder, "optionsBuilder cannot be null");
    }

    protected abstract S self();

    @Override
    public S rawHttp(SafeHttpCustomizer customizer) {
        this.optionsBuilder.rawHttp(wrapSafeHttpCustomizer(customizer));
        return self();
    }

    @Override
    public S disableCsrf() {
        this.optionsBuilder.disableCsrf();
        return self();
    }

    @Override
    public S cors(Customizer<CorsConfigurer<HttpSecurity>> customizer) {
        this.optionsBuilder.cors(customizer);
        return self();
    }

    @Override
    public S headers(Customizer<HeadersConfigurer<HttpSecurity>> customizer) {
        this.optionsBuilder.headers(customizer);
        return self();
    }

    @Override
    public S sessionManagement(Customizer<SessionManagementConfigurer<HttpSecurity>> customizer) {
        this.optionsBuilder.sessionManagement(customizer);
        return self();
    }

    @Override
    public S logout(Customizer<LogoutConfigurer<HttpSecurity>> customizer) {
        this.optionsBuilder.logout(customizer);
        return self();
    }

    protected Customizer<HttpSecurity> wrapSafeHttpCustomizer(SafeHttpCustomizer safeCustomizer) {
        return http -> {
            try {
                if (safeCustomizer != null) safeCustomizer.customize(http);
            } catch (Exception e) {
                throw new DslConfigurationException("Error during raw HttpSecurity customization: " + e.getMessage(), e);
            }
        };
    }

    protected Customizer<FormLoginConfigurer<HttpSecurity>> wrapSafeFormLoginCustomizer(SafeHttpFormLoginCustomizer safeCustomizer) {
        return formLogin -> {
            try {
                if (safeCustomizer != null) safeCustomizer.customize(formLogin);
            } catch (Exception e) {
                throw new DslConfigurationException("Error during raw FormLoginConfigurer customization: " + e.getMessage(), e);
            }
        };
    }

    @Override
    public O buildConcreteOptions() {
        return this.optionsBuilder.build();
    }
}
