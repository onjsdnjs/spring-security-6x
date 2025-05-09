package io.springsecurity.springsecurity6x.security.core.dsl.common;

import io.springsecurity.springsecurity6x.security.core.dsl.FormDslConfigurer;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.*;
import org.springframework.util.function.ThrowingConsumer;

/**
 * 공통 DSL 인터페이스
 *
 * @param <T> DSL self type
 */
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
    T logout(Customizer<LogoutConfigurer<HttpSecurity>> customizer);

    /**
     * Advanced: raw FormLoginConfigurer access for full API coverage
     */
    T raw(SafeHttpCustomizer customizer);

    ThrowingConsumer<HttpSecurity> toFlowCustomizer();

    T order(int order);
}
