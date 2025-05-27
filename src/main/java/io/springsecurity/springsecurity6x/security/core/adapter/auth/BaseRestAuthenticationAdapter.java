package io.springsecurity.springsecurity6x.security.core.adapter.auth;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.option.RestOptions;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

/**
 * REST 인증 어댑터 기반 클래스
 * @param <T> Configurer 타입
 */
public abstract class BaseRestAuthenticationAdapter<T extends AbstractHttpConfigurer<T, HttpSecurity>>
        extends AbstractAuthenticationAdapter<RestOptions> {

    @Override
    public int getOrder() {
        return 200;
    }

    @Override
    protected void configureHttpSecurity(HttpSecurity http, RestOptions opts,
                                         AuthenticationFlowConfig currentFlow,
                                         AuthenticationSuccessHandler successHandler,
                                         AuthenticationFailureHandler failureHandler) throws Exception {

        T configurer = createConfigurer();

        http.with(configurer, config -> {
            configureRestAuthentication(config, opts, successHandler, failureHandler);

            if (opts.getSecurityContextRepository() != null) {
                configureSecurityContext(config, opts);
            }
        });
    }

    /**
     * Configurer 인스턴스 생성
     */
    protected abstract T createConfigurer();

    /**
     * REST 인증 설정
     */
    protected abstract void configureRestAuthentication(T configurer, RestOptions opts,
                                                        AuthenticationSuccessHandler successHandler,
                                                        AuthenticationFailureHandler failureHandler);

    /**
     * Security Context 설정
     */
    protected abstract void configureSecurityContext(T configurer, RestOptions opts);
}