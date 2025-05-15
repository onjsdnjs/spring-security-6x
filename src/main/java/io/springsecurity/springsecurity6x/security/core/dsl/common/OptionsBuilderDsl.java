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

public interface OptionsBuilderDsl<O extends AuthenticationProcessingOptions, S extends OptionsBuilderDsl<O, S>> {

    // CommonSecurityDsl (AbstractOptions 관련)
    S disableCsrf();
    S cors(Customizer<CorsConfigurer<HttpSecurity>> customizer);
    S headers(Customizer<HeadersConfigurer<HttpSecurity>> customizer);
    S sessionManagement(Customizer<SessionManagementConfigurer<HttpSecurity>> customizer);
    S logout(Customizer<LogoutConfigurer<HttpSecurity>> customizer);
    S rawHttp(SafeHttpCustomizer<HttpSecurity> customizer);

    // AuthenticationProcessingOptions 관련 공통 설정
    S loginProcessingUrl(String url);
    S successHandler(AuthenticationSuccessHandler handler);
    S failureHandler(AuthenticationFailureHandler handler);
    S securityContextRepository(SecurityContextRepository repository);
    O buildConcreteOptions(); // 최종 Option 객체 생성
}

