package io.springsecurity.springsecurity6x.security.core.feature.auth.form;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.StateConfig;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import io.springsecurity.springsecurity6x.security.core.dsl.option.FormOptions;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;

import java.util.List;
import java.util.Objects;

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
        Object optsObj = step.options().get("_options");
        if (!(optsObj instanceof FormOptions opts)) {
            throw new IllegalStateException("Expected FormOptions");
        }

        http.formLogin(form -> {
            // apply basic options
            form.loginPage(opts.getLoginPage())
                    .loginProcessingUrl(opts.getLoginProcessingUrl())
                    .usernameParameter(opts.getUsernameParameter())
                    .passwordParameter(opts.getPasswordParameter())
                    .defaultSuccessUrl(opts.getDefaultSuccessUrl(), opts.isAlwaysUseDefaultSuccessUrl())
                    .failureUrl(opts.getFailureUrl())
                    .permitAll(opts.isPermitAll());

            if (opts.getSuccessHandler() != null) form.successHandler(opts.getSuccessHandler());
            if (opts.getFailureHandler() != null) form.failureHandler(opts.getFailureHandler());
            if (opts.getSecurityContextRepository() != null) form.securityContextRepository(opts.getSecurityContextRepository());

            // raw FormLoginConfigurer 커스터마이저
            Customizer<FormLoginConfigurer<HttpSecurity>> rawLogin = opts.getRawFormLogin();
            if (rawLogin != null) {
                rawLogin.customize(form);
            }
        });
        // raw HttpSecurity 커스터마이저들 적용
        List<Customizer<HttpSecurity>> httpCustomizers = opts.rawHttpCustomizers();
        for (Customizer<HttpSecurity> customizer : httpCustomizers) {
            Objects.requireNonNull(customizer, "rawHttp customizer must not be null").customize(http);
        }
    }
}

