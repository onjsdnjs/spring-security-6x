package io.springsecurity.springsecurity6x.security.core.dsl.common;

import io.springsecurity.springsecurity6x.security.core.dsl.option.AbstractOptions;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CorsConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;

public interface OptionsBuilderDsl<O extends AbstractOptions, S extends OptionsBuilderDsl<O, S>> {

    /**
     * 모든 HTTP 관련 설정의 진입점
     */
    default S rawHttp(SafeHttpCustomizer customizer) {
        // 현재는 간단히 체이닝만 지원하도록 this를 반환
        return (S) this;
    }

    /**
     * CSRF 비활성화
     */
    default S disableCsrf() {
        // 예시: rawHttp를 이용해 CSRF 비활성화 설정을 위임할 수 있음
        return rawHttp(http -> http.csrf(Customizer.withDefaults()));
    }

    /**
     * CORS 설정
     */
    default S cors(Customizer<CorsConfigurer<HttpSecurity>> customizer) {
        return rawHttp(http -> http.cors(Customizer.withDefaults()));
    }

    /**
     * HTTP headers 설정
     */
    default S headers(Customizer<HeadersConfigurer<HttpSecurity>> customizer) {
        return rawHttp(http -> http.headers(Customizer.withDefaults()));
    }

    /**
     * 세션 관리 설정
     */
    default S sessionManagement(Customizer<SessionManagementConfigurer<HttpSecurity>> customizer) {
        return rawHttp(http -> http.sessionManagement(Customizer.withDefaults()));
    }

    /**
     * 로그아웃 설정
     */
    default S logout(Customizer<LogoutConfigurer<HttpSecurity>> customizer) {
        return rawHttp(http -> http.logout(Customizer.withDefaults()));
    }

    /**
     * 최종 Options 객체를 생성
     * 구현체에서 반드시 오버라이드하세요.
     */
    default O buildConcreteOptions() {
        throw new UnsupportedOperationException("buildConcreteOptions()를 구현체에서 반드시 재정의해야 합니다.");
    }
}

