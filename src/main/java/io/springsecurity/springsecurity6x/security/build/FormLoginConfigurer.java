/*
package io.springsecurity.springsecurity6x.security.build;

import io.springsecurity.springsecurity6x.security.core.feature.option.FormOptions;
import io.springsecurity.springsecurity6x.security.init.AuthenticationConfig;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

*/
/**
 * Form 기반 로그인 전략을 적용하는 Configurer.
 *//*

public class FormLoginConfigurer implements IdentitySecurityConfigurer {

    // 필요시 기본 핸들러 주입
    // private final AuthenticationHandlers defaultHandlers;
    //
    // public FormLoginConfigurer(AuthenticationHandlers defaultHandlers) {
    //     this.defaultHandlers = defaultHandlers;
    // }

    @Override
    public boolean supports(AuthenticationConfig config) {
        return "form".equalsIgnoreCase(config.type());
    }

    @Override
    public void configure(HttpSecurity http, AuthenticationConfig config) throws Exception {
        FormOptions options = (FormOptions) config.options();

        // 1) URL 매처 설정
        if (options.getMatchers() != null && !options.getMatchers().isEmpty()) {
            http.securityMatcher(options.getMatchers().toArray(new String[0]));
        }

        // 2) Form 로그인 설정
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

            // 3) 성공/실패 핸들러 (없으면 스프링 기본)
            if (options.getSuccessHandler() != null) {
                form.successHandler(options.getSuccessHandler());
            }
            if (options.getFailureHandler() != null) {
                form.failureHandler(options.getFailureHandler());
            }

            // 4) SecurityContextRepository (없으면 스프링 기본)
            if (options.getSecurityContextRepository() != null) {
                form.securityContextRepository(options.getSecurityContextRepository());
            }
        });
    }

    @Override
    public void init(HttpSecurity http) throws Exception {
        // 별도 초기화가 필요하면 여기에 구현
    }

    @Override
    public int order() {
        return 100; // 인증 처리 configurer는 100번대
    }
}


*/
