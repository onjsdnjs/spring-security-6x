package io.springsecurity.springsecurity6x.security.core.feature.impl;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.StateConfig;
import io.springsecurity.springsecurity6x.security.core.feature.option.FormOptions;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.List;

/**
 * Form 기반 로그인 전략을 적용하는 Feature 구현체
 */
public class FormAuthenticationFeature implements AuthenticationFeature {
    @Override
    public String getId() {
        return AuthType.FORM.name().toLowerCase();
    }
    @Override public int getOrder() { return 100; }

    /**
     * @param http HttpSecurity
     * @param steps DSL로 정의된 인증 단계 설정 리스트 (여기서는 FormOptions로 변환 가능)
     * @param state 최종 인증 상태 (session, jwt 등)
     */
    @Override
    public void apply(HttpSecurity http, List<AuthenticationStepConfig> steps, StateConfig state) throws Exception {
        if (steps == null || steps.isEmpty()) {
            return;
        }
        // 첫 번째 단계만 처리
        AuthenticationStepConfig step = steps.getFirst();
        // FormOptions 객체는 별도 공유 컨텍스트에서 가져오거나, step.options에서 복원
        FormOptions opts = (FormOptions) step.getOptions().get("_options");
        // 공통 설정 (CSRF, CORS 등) 이미 적용됨

        // URL matcher
        if (step.getMatchers() != null && step.getMatchers().length > 0) {
            http.securityMatcher(step.getMatchers());
        }

        // form login 설정
        http.formLogin(form -> {
            form.loginPage(opts.getLoginPage())
                    .loginProcessingUrl(opts.getLoginProcessingUrl())
                    .usernameParameter(opts.getUsernameParameter())
                    .passwordParameter(opts.getPasswordParameter())
                    .defaultSuccessUrl(opts.getDefaultSuccessUrl(), opts.isAlwaysUseDefaultSuccessUrl())
                    .failureUrl(opts.getFailureUrl());
            if (opts.getSuccessHandler() != null) {
                form.successHandler(opts.getSuccessHandler());
            }
            if (opts.getFailureHandler() != null) {
                form.failureHandler(opts.getFailureHandler());
            }
            if (opts.getSecurityContextRepository() != null) {
                form.securityContextRepository(opts.getSecurityContextRepository());
            }
        });
    }
}

