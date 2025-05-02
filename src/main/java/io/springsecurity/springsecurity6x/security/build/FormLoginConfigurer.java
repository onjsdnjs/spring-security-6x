package io.springsecurity.springsecurity6x.security.build;

import io.springsecurity.springsecurity6x.security.build.option.FormOptions;
import io.springsecurity.springsecurity6x.security.init.AuthenticationConfig;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * Form 기반 로그인 전략을 적용하는 Configurer.
 */
public class FormLoginConfigurer implements IdentitySecurityConfigurer {

    @Override
    public boolean supports(AuthenticationConfig config) {
        return "form".equalsIgnoreCase(config.type());
    }

    @Override
    public void configure(HttpSecurity http, AuthenticationConfig config) throws Exception {
        FormOptions options = (FormOptions) config.options();
        if (options.matchers() != null && !options.matchers().isEmpty()) {
            http.securityMatcher(options.matchers().toArray(new String[0]));
        }

        http.formLogin(form -> {
            form
                .loginPage(options.loginPage())
                .loginProcessingUrl(options.loginProcessingUrl())
                .usernameParameter(options.usernameParameter())
                .passwordParameter(options.passwordParameter())
                .defaultSuccessUrl(options.defaultSuccessUrl(), options.alwaysUseDefaultSuccessUrl())
                .failureUrl(options.failureUrl());

            if (options.successHandler() != null) {
                form.successHandler(options.successHandler());
            } else {
//                form.successHandler(authenticationHandlers.successHandler());
            }
            if (options.failureHandler() != null) {
                form.failureHandler(options.failureHandler());
            } else {
//                form.failureHandler(authenticationHandlers.failureHandler());
            }

            if (options.securityContextRepository() != null) {
                form.securityContextRepository(options.securityContextRepository());
            }
        });
    }

    @Override
    public void init(HttpSecurity http) throws Exception {

    }

    @Override
    public int order() {
        return 100; // 인증 처리 configurer는 100번대
    }
}

