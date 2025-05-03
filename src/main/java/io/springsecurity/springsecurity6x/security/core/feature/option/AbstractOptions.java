package io.springsecurity.springsecurity6x.security.core.feature.option;

import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CorsConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;

import java.util.List;

/**
 * CSRF, CORS, Header, Session, Static 리소스 허용 등 공통 보안 옵션을 추상화한 불변 객체
 */
public abstract class AbstractOptions {
    private final boolean csrfDisabled;
    private final Customizer<CorsConfigurer<HttpSecurity>> corsCustomizer;
    private final Customizer<HeadersConfigurer<HttpSecurity>> headersCustomizer;
    private final Customizer<SessionManagementConfigurer<HttpSecurity>> sessionManagementCustomizer;
    private final List<String> staticMatchers;

    protected AbstractOptions(Builder<?, ?> b) {
        this.csrfDisabled = b.csrfDisabled;
        this.corsCustomizer = b.corsCustomizer;
        this.headersCustomizer = b.headersCustomizer;
        this.sessionManagementCustomizer = b.sessionManagementCustomizer;
        this.staticMatchers = List.copyOf(b.staticMatchers);
    }

    /** 공통 옵션을 HttpSecurity에 적용 */
    public void applyCommon(HttpSecurity http) throws Exception {
        if (csrfDisabled) {
            http.csrf(AbstractHttpConfigurer::disable);
        }
        if (corsCustomizer != null) {
            http.cors(corsCustomizer);
        }
        if (headersCustomizer != null) {
            http.headers(headersCustomizer);
        }
        if (sessionManagementCustomizer != null) {
            http.sessionManagement(sessionManagementCustomizer);
        }
        if (!staticMatchers.isEmpty()) {
            http.authorizeHttpRequests(a -> a.requestMatchers(staticMatchers.toArray(new String[0])).permitAll());
        }
    }

    /**
     * AbstractOptions Builder
     */
    public static abstract class Builder<O extends AbstractOptions, B extends Builder<O, B>> {
        private boolean csrfDisabled = false;
        private Customizer<CorsConfigurer<HttpSecurity>> corsCustomizer;
        private Customizer<HeadersConfigurer<HttpSecurity>> headersCustomizer;
        private Customizer<SessionManagementConfigurer<HttpSecurity>> sessionManagementCustomizer;
        private List<String> staticMatchers = List.of();

        protected abstract B self();

        public B disableCsrf() {
            this.csrfDisabled = true;
            return self();
        }

        public B cors(Customizer<CorsConfigurer<HttpSecurity>> customizer) {
            this.corsCustomizer = customizer;
            return self();
        }

        public B headers(Customizer<HeadersConfigurer<HttpSecurity>> customizer) {
            this.headersCustomizer = customizer;
            return self();
        }

        public B sessionManagement(Customizer<SessionManagementConfigurer<HttpSecurity>> customizer) {
            this.sessionManagementCustomizer = customizer;
            return self();
        }

        public B authorizeStatic(List<String> patterns) {
            this.staticMatchers = List.copyOf(patterns);
            return self();
        }

        public abstract O build();
    }
}