package io.springsecurity.springsecurity6x.security.core.feature.impl;

import io.springsecurity.springsecurity6x.security.build.option.FormOptions;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import io.springsecurity.springsecurity6x.security.handler.authentication.AuthenticationHandlers;
import io.springsecurity.springsecurity6x.security.init.AuthenticationConfig;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;

import java.util.Objects;

/**
 * Form 로그인 전략을 HttpSecurity에 적용하는 AuthenticationFeature 구현체입니다.
 * 주어진 AuthenticationConfig에서 FormOptions를 꺼내어,
 *  - URL 매처(matchers)
 *  - 로그인 페이지
 *  - 로그인 처리 URL
 *  - 파라미터 이름(username/password)
 *  - 성공/실패 핸들러
 *  - 보안 컨텍스트 리포지토리
 * 등을 설정합니다.
 */
public class FormAuthenticationFeature implements AuthenticationFeature {

    private final AuthenticationHandlers defaultHandlers;

    /**
     * @param defaultHandlers 기본 성공/실패 핸들러 및 SecurityContextRepository 제공자
     */
    public FormAuthenticationFeature(AuthenticationHandlers defaultHandlers) {
        this.defaultHandlers = defaultHandlers;
    }

    @Override
    public String getId() {
        return "form";
    }

    @Override
    public void apply(HttpSecurity http, PlatformContext ctx) throws Exception {
        // Context에서 현재 AuthenticationConfig를 꺼낸다
        AuthenticationConfig config = ctx.getShared(AuthenticationConfig.class);
        FormOptions opts = (FormOptions) config.options();

        // 1) URL 매처 설정
        if (opts.matchers() != null && !opts.matchers().isEmpty()) {
            http.securityMatcher(opts.matchers().toArray(new String[0]));
        }

        // 2) Form 로그인 설정
        http.formLogin(form -> {
            form.loginPage(opts.loginPage())
                    .loginProcessingUrl(opts.loginProcessingUrl())
                    .usernameParameter(opts.usernameParameter())
                    .passwordParameter(opts.passwordParameter())
                    .defaultSuccessUrl(opts.defaultSuccessUrl(), opts.alwaysUseDefaultSuccessUrl())
                    .failureUrl(opts.failureUrl());

            // 3) 성공/실패 핸들러 설정 (옵션이 없으면 기본 핸들러 사용)
            AuthenticationSuccessHandler successHandler = Objects.requireNonNullElse(
                    opts.successHandler(),
                    defaultHandlers.successHandler()
            );
            AuthenticationFailureHandler failureHandler = Objects.requireNonNullElse(
                    opts.failureHandler(),
                    defaultHandlers.failureHandler()
            );
            form.successHandler(successHandler);
            form.failureHandler(failureHandler);

            // 4) SecurityContextRepository 설정
           /* SecurityContextRepository repo = Objects.requireNonNullElse(
                    opts.securityContextRepository(),
                    defaultHandlers.securityContextRepository()
            );
            form.securityContextRepository(repo);*/
        });
    }
}
