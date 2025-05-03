package io.springsecurity.springsecurity6x.security.core.feature.impl;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationConfig;
import io.springsecurity.springsecurity6x.security.core.feature.option.RestOptions;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import io.springsecurity.springsecurity6x.security.handler.authentication.AuthenticationHandlers;
import io.springsecurity.springsecurity6x.security.core.RestAuthenticationConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.util.Objects;

/**
 * REST 기반 로그인 전략을 HttpSecurity에 적용하는 AuthenticationFeature 구현체입니다.
 *
 * - DSL로 설정된 RestOptions(matchers, loginProcessingUrl, defaultSuccessUrl, failureUrl 등)을
 *   HttpSecurity.with(RestAuthenticationConfigurer) 블록 안에서 구성합니다.
 * - 성공/실패 핸들러와 SecurityContextRepository는 옵션이 없으면 기본 핸들러(provider를 통해 주입된)를 사용합니다.
 */
public class RestAuthenticationFeature implements AuthenticationFeature {

    private final AuthenticationHandlers defaultHandlers;

    /**
     * @param defaultHandlers 기본 Success/Failure 핸들러 및 SecurityContextRepository 제공자
     */
    public RestAuthenticationFeature(AuthenticationHandlers defaultHandlers) {
        this.defaultHandlers = defaultHandlers;
    }

    @Override
    public String getId() {
        return "rest";
    }

    @Override
    public void apply(HttpSecurity http, PlatformContext ctx) throws Exception {
        // 1) PlatformContext에서 현재 AuthenticationConfig를 꺼냅니다.
        AuthenticationConfig config = ctx.getShared(AuthenticationConfig.class);
        RestOptions opts = (RestOptions) config.options();

        // 2) 요청 매처 설정
        if (opts.getMatchers() != null && !opts.getMatchers().isEmpty()) {
            http.securityMatcher(opts.getMatchers().toArray(new String[0]));
        }

        // 3) RestAuthenticationConfigurer 적용
        http.with(new RestAuthenticationConfigurer(), rest -> {
            rest.loginProcessingUrl(opts.getLoginProcessingUrl())
                    .defaultSuccessUrl(opts.getDefaultSuccessUrl())
                    .failureUrl(opts.getFailureUrl());

            // 4) 성공/실패 핸들러 설정 (옵션 없으면 기본 사용)
            AuthenticationSuccessHandler successHandler = Objects.requireNonNullElse(
                    opts.getSuccessHandler(),
                    defaultHandlers.successHandler()
            );
            AuthenticationFailureHandler failureHandler = Objects.requireNonNullElse(
                    opts.getFailureHandler(),
                    defaultHandlers.failureHandler()
            );
            rest.successHandler(successHandler);
            rest.failureHandler(failureHandler);

            // 5) SecurityContextRepository 설정
            /*SecurityContextRepository repo = Objects.requireNonNullElse(
                    opts.securityContextRepository(),
                    defaultHandlers.securityContextRepository()
            );
            rest.securityContextRepository(repo);*/
        });
    }
}

