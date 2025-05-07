package io.springsecurity.springsecurity6x.security.core.feature.authentication;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.StateConfig;
import io.springsecurity.springsecurity6x.security.core.dsl.RestAuthenticationConfigurer;
import io.springsecurity.springsecurity6x.security.core.dsl.option.RestOptions;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.util.List;
import java.util.Objects;

/**
 * REST 기반 로그인 전략을 HttpSecurity에 적용하는 AuthenticationFeature 구현체입니다.
 *
 * - DSL로 설정된 RestOptions(matchers, loginProcessingUrl, defaultSuccessUrl, failureUrl 등)을
 *   HttpSecurity.with(RestAuthenticationConfigurer) 블록 안에서 구성합니다.
 * - 성공/실패 핸들러와 SecurityContextRepository는 옵션이 없으면 기본 핸들러(provider를 통해 주입된)를 사용합니다.
 */
public class RestAuthenticationFeature implements AuthenticationFeature {

    @Override
    public String getId() {
        return "rest";
    }

    @Override
    public int getOrder() {
        return 200;
    }

    @Override
    public void apply(HttpSecurity http, List<AuthenticationStepConfig> steps, StateConfig state) throws Exception {
        if (steps == null || steps.isEmpty()) {
            return;
        }
        AuthenticationStepConfig step = steps.getFirst();

        Object optsObj = step.options().get("_options");
        if (!(optsObj instanceof RestOptions opts)) {
            throw new IllegalStateException("Expected RestOptions in step options");
        }

        http.with(new RestAuthenticationConfigurer(), rest -> {
            rest
                .loginPage(opts.getLoginPage())
                .loginProcessingUrl(opts.getLoginProcessingUrl())
                .defaultSuccessUrl(opts.getDefaultSuccessUrl())
                .failureUrl(opts.getFailureUrl());

            if (opts.getSuccessHandler() != null)
                rest.successHandler(opts.getSuccessHandler());
            if (opts.getFailureHandler() != null)
                rest.failureHandler(opts.getFailureHandler());
            if (opts.getSecurityContextRepository() != null)
                rest.securityContextRepository(opts.getSecurityContextRepository());
        });
    }
}

