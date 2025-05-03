package io.springsecurity.springsecurity6x.security.core.feature.impl;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.StateConfig;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import io.springsecurity.springsecurity6x.security.core.feature.option.FormOptions;
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

        if (steps == null || steps.isEmpty()) return;
        AuthenticationStepConfig step = steps.getFirst();
        Object optsObj = step.getOptions().get("_options");
        if (!(optsObj instanceof FormOptions opts)) {
            throw new IllegalStateException("Expected FormOptions in step options");
        }
        if (!opts.getMatchers().isEmpty()) {
            http.securityMatcher(opts.getMatchers().toArray(new String[0]));
        }

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

