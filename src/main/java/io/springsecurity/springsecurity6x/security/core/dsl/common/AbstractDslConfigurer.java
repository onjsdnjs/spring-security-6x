package io.springsecurity.springsecurity6x.security.core.dsl.common;

import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CorsConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.util.function.ThrowingConsumer;

import java.util.ArrayList;
import java.util.List;

/**
 * 예외 없이 깔끔하게 공통 보안 설정을 적용할 수 있는 DSL 구현체
 */
public abstract class AbstractDslConfigurer<T extends AbstractDslConfigurer<T>>
        implements CommonSecurityDsl<T> {

    protected final List<ThrowingConsumer<HttpSecurity>> commonCustomizers = new ArrayList<>();

    protected T self() {
        return (T) this;
    }

    @Override
    public T disableCsrf() {
        commonCustomizers.add(http -> http.csrf(AbstractHttpConfigurer::disable));
        return self();
    }

    @Override
    public T cors(Customizer<CorsConfigurer<HttpSecurity>> customizer) {
        commonCustomizers.add(http -> http.cors(customizer));
        return self();
    }

    @Override
    public T headers(Customizer<HeadersConfigurer<HttpSecurity>> customizer) {
        commonCustomizers.add(http -> http.headers(customizer));
        return self();
    }

    @Override
    public T sessionManagement(Customizer<SessionManagementConfigurer<HttpSecurity>> customizer) {
        commonCustomizers.add(http -> http.sessionManagement(customizer));
        return self();
    }

    @Override
    public T authorizeStatic(String... patterns) {
        commonCustomizers.add(http ->
                http.authorizeHttpRequests(a -> a.requestMatchers(patterns).permitAll())
        );
        return self();
    }

    /**
     * 공통 설정들을 HttpSecurity에 실제 적용합니다.
     */
    protected void applyCommon(HttpSecurity http) throws Exception {
        for (var c : commonCustomizers) {
            c.accept(http);
        }
    }

    /**
     * 공통 설정 후에 securityMatcher 까지 적용할 때 사용합니다.
     */
    protected void applyCommonWithMatcher(HttpSecurity http, String... patterns) throws Exception {
        applyCommon(http);
        if (patterns != null && patterns.length > 0) {
            http.securityMatcher(patterns);
        }
    }
}