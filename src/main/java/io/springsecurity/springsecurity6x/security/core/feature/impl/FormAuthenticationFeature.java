package io.springsecurity.springsecurity6x.security.core.feature.impl;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationConfig;
import io.springsecurity.springsecurity6x.security.core.feature.option.FormOptions;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * Form 기반 로그인 전략을 적용하는 Feature 구현체
 */
public class FormAuthenticationFeature implements AuthenticationFeature {
    @Override
    public String getId() {
        // AuthType enum 기반 식별자 (소문자)
        return AuthType.FORM.name().toLowerCase();
    }

    @Override
    public void apply(HttpSecurity http, PlatformContext ctx) throws Exception {
        // 1) DSL 단계에서 저장된 AuthenticationConfig를 꺼내고, 옵션 객체를 가져온다
        AuthenticationConfig config = ctx.getShared(AuthenticationConfig.class);
        FormOptions options = (FormOptions) config.options();

        // 2) AbstractOptions에 정의된 공통 보안 설정(CSRF, CORS, Headers, Session, Static 리소스)을 먼저 적용
        options.applyCommon(http);

        // 3) URL 매처(인증이 적용될 패턴) 설정
        if (!options.getMatchers().isEmpty()) {
            http.securityMatcher(options.getMatchers().toArray(new String[0]));
        }

        // 4) 폼 로그인 설정
        http.formLogin(form -> {
            form
                    .loginPage(options.getLoginPage())
                    .loginProcessingUrl(options.getLoginProcessingUrl())
                    .usernameParameter(options.getUsernameParameter())
                    .passwordParameter(options.getPasswordParameter())
                    .defaultSuccessUrl(
                            options.getDefaultSuccessUrl(),
                            options.isAlwaysUseDefaultSuccessUrl()
                    )
                    .failureUrl(options.getFailureUrl());

            // 5) 성공/실패 핸들러 (없으면 스프링 기본 사용)
            if (options.getSuccessHandler() != null) {
                form.successHandler(options.getSuccessHandler());
            }
            if (options.getFailureHandler() != null) {
                form.failureHandler(options.getFailureHandler());
            }

            // 6) SecurityContextRepository (없으면 스프링 기본 사용)
            if (options.getSecurityContextRepository() != null) {
                form.securityContextRepository(options.getSecurityContextRepository());
            }
        });
    }
}

