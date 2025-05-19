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

// O: Options 타입, S: DSL Configurer 자신의 타입
public interface OptionsBuilderDsl<O extends AuthenticationProcessingOptions, S extends OptionsBuilderDsl<O, S>> {

    S disableCsrf();
    S cors(Customizer<CorsConfigurer<HttpSecurity>> customizer);
    S headers(Customizer<HeadersConfigurer<HttpSecurity>> customizer);
    S sessionManagement(Customizer<SessionManagementConfigurer<HttpSecurity>> customizer);
    S logout(Customizer<LogoutConfigurer<HttpSecurity>> customizer);
    S rawHttp(SafeHttpCustomizer<HttpSecurity> customizer); // 플랫폼 고유 Customizer

    S loginProcessingUrl(String url);
    S successHandler(AuthenticationSuccessHandler handler);
    S failureHandler(AuthenticationFailureHandler handler);
    S securityContextRepository(SecurityContextRepository repository);

    O buildConcreteOptions();
}

