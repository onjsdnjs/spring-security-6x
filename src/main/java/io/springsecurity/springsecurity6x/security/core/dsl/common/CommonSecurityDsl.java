package io.springsecurity.springsecurity6x.security.core.dsl.common;

import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CorsConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;

public interface CommonSecurityDsl<T> {

    /** CSRF 비활성화 **/
    T disableCsrf();

    /** CORS 설정 **/
    T cors(Customizer<CorsConfigurer<HttpSecurity>> customizer);

    /** Header 정책 설정 **/
    T headers(Customizer<HeadersConfigurer<HttpSecurity>> customizer);

    /** 세션 관리 설정 **/
    T sessionManagement(Customizer<SessionManagementConfigurer<HttpSecurity>> customizer);

    /** 정적 리소스 허용 패턴 **/
    T authorizeStatic(String... patterns);
}
