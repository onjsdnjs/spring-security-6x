package io.springsecurity.springsecurity6x.security.build;

import io.springsecurity.springsecurity6x.security.dsl.authentication.single.FormAuthenticationDsl;
import io.springsecurity.springsecurity6x.security.init.AuthenticationConfig;
import io.springsecurity.springsecurity6x.security.build.option.FormOptions;
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

        FormAuthenticationDsl dsl = new FormAuthenticationDsl()
                .loginPage(options.loginPage())
                .loginProcessingUrl(options.loginProcessingUrl())
                .usernameParameter(options.usernameParameter())
                .passwordParameter(options.passwordParameter())
                .defaultSuccessUrl(options.defaultSuccessUrl(), options.alwaysUseDefaultSuccessUrl())
                .failureUrl(options.failureUrl());

        if (options.successHandler() != null) {
            dsl.successHandler(options.successHandler());
        }
        if (options.failureHandler() != null) {
            dsl.failureHandler(options.failureHandler());
        }
        if (options.securityContextRepository() != null) {
            dsl.securityContextRepository(options.securityContextRepository());
        }

        dsl.configure(http);
    }

    @Override
    public int order() {
        return 100; // 인증 처리 configurer는 100번대
    }
}

