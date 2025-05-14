package io.springsecurity.springsecurity6x.security.core.dsl.common;

import io.springsecurity.springsecurity6x.security.core.dsl.option.AbstractOptions;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CorsConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;

public interface OptionsBuilderDsl<O extends AbstractOptions, S extends OptionsBuilderDsl<O, S>> {
    S rawHttp(SafeHttpCustomizer customizer);
    S disableCsrf();
    S cors(Customizer<CorsConfigurer<HttpSecurity>> customizer);
    S headers(Customizer<HeadersConfigurer<HttpSecurity>> customizer);
    S sessionManagement(Customizer<SessionManagementConfigurer<HttpSecurity>> customizer);
    S logout(Customizer<LogoutConfigurer<HttpSecurity>> customizer);
    O buildConcreteOptions();
}
