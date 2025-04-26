package io.springsecurity.springsecurity6x.security.dsl.authentication;

import io.springsecurity.springsecurity6x.security.dsl.AbstractAuthenticationDsl;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public final class FormAuthenticationDsl extends AbstractAuthenticationDsl {
    private String loginPage = "/login";

    public FormAuthenticationDsl loginPage(String p) { this.loginPage = p; return this; }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.formLogin(f -> f
                .loginPage(loginPage)
                .successHandler(stateStrategy.successHandler())
                .failureHandler(stateStrategy.failureHandler())
        );
    }
}
